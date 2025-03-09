using System.Text;
using Microsoft.Extensions.Options;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core;

public sealed class Attestation : IAttestation
{
    private const ulong DefaultTimeout = 60000;

    private readonly IClientDataHandler _clientDataHandler;
    private readonly IAttestationObjectHandler _attestationObjectHandler;
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly ICredentialRepository _credentialRepository;
    private readonly Fido2Configuration _configuration;

    public Attestation(
        IClientDataHandler clientDataHandler,
        IAttestationObjectHandler attestationObjectHandler,
        IChallengeGenerator challengeGenerator,
        ICredentialRepository credentialRepository,
        IOptions<Fido2Configuration> options)
    {
        _clientDataHandler = clientDataHandler;
        _attestationObjectHandler = attestationObjectHandler;
        _challengeGenerator = challengeGenerator;
        _credentialRepository = credentialRepository;
        _configuration = options.Value;
    }

    public PublicKeyCredentialCreationOptions GetOptions(PublicKeyCredentialCreationOptionsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions
        {
            RelyingParty = new PublicKeyCredentialRpEntity
            {
                Id = _configuration.RelyingPartyId,
                Name = _configuration.RelyingPartyIdName,
            },
            User = new PublicKeyCredentialUserEntity
            {
                Id = Encoding.UTF8.GetBytes(request.Username),
                Name = request.Username,
                DisplayName = request.DisplayName,
            },
            Challenge = _challengeGenerator.Get(),
            PublicKeyCredentialParams =
            [
                new PublicKeyCredentialParameter { Algorithm = PublicKeyAlgorithm.Es256 },
                new PublicKeyCredentialParameter { Algorithm = PublicKeyAlgorithm.Rs256 },
            ],
            Timeout = _configuration.Timeout ?? DefaultTimeout,
            ExcludeCredentials = [],
            AuthenticatorSelection = request.AuthenticatorSelection != null ? new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = request.AuthenticatorSelection.AuthenticatorAttachment,
                ResidentKey = request.AuthenticatorSelection.ResidentKey,
                RequireResidentKey = request.AuthenticatorSelection.RequireResidentKey,
                UserVerification = request.AuthenticatorSelection.UserVerification ??
                    UserVerificationRequirement.Preferred,
            } : new AuthenticatorSelectionCriteria(),
            Attestation = request.Attestation ?? AttestationConveyancePreference.None,
            Extensions = new AuthenticationExtensionsClientInputs(),
        };

        return credentialCreationOptions;
    }

    public async Task<AttestationCompleteResult> Complete(
        PublicKeyCredentialAttestation publicKeyCredentialAttestation,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialAttestation);
        ArgumentNullException.ThrowIfNull(creationOptions);

        // 7.1. Registering a New Credential

        // Step 3
        // Let response be credential.response. If response is not an instance of AuthenticatorAttestationResponse,
        // abort the ceremony with a user-visible error.
        var response = publicKeyCredentialAttestation.Response;
        if (response == null)
        {
            return AttestationCompleteResult.CreateFailure("Attestation response cannot be null");
        }

        // Steps 5 to 12
        var challengeString = Convert.ToBase64String(creationOptions.Challenge);
        var clientDataHandlerResult = _clientDataHandler.HandleAttestation(response.ClientDataJson, challengeString);
        if (clientDataHandlerResult.HasError)
        {
            return AttestationCompleteResult.CreateFailure(clientDataHandlerResult.Message!);
        }

        // Steps 13 to 21
        var attestationResult = _attestationObjectHandler.Handle(
            response.AttestationObject,
            clientDataHandlerResult.Value!,
            creationOptions);
        if (attestationResult.HasError)
        {
            // Step 24
            // If the attestation statement attStmt successfully verified but is not trustworthy per step 21 above,
            // the Relying Party SHOULD fail the registration ceremony.
            return AttestationCompleteResult.CreateFailure(attestationResult.Message!);
        }

        // Step 22
        // Check that the credentialId is not yet registered to any other user. If registration is requested for a
        // credential that is already registered to a different user, the Relying Party SHOULD fail this registration
        // ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.
        var attestedCredentialData = attestationResult.Value!.AuthenticatorData!.AttestedCredentialData;
        var credentialId = attestedCredentialData!.CredentialId;
        var credential = await _credentialRepository.Get(credentialId);
        if (credential != null)
        {
            return AttestationCompleteResult.CreateFailure("Credential has already been registered");
        }

        // Step 23
        // If the attestation statement attStmt verified successfully and is found to be trustworthy, then register
        // the new credential with the account that was denoted in options.user:
        // - Associate the user's account with the credentialId and credentialPublicKey in
        // authData.attestedCredentialData, as appropriate for the Relying Party's system.
        // - Associate the credentialId with a new stored signature counter value initialized to the value of
        // authData.signCount.
        // Associate the credentialId with the transport hints returned by calling credential.response.getTransports().
        // This value SHOULD NOT be modified before or after storing it. It is RECOMMENDED to use this value to
        // populate the transports of the allowCredentials option in future get() calls to help the client know how
        // to find a suitable authenticator.
        credential = new Credential
        {
            CredentialId = credentialId!,
            UserHandle = creationOptions.User.Id,
            Username = creationOptions.User.Name,
            CredentialPublicKey = attestedCredentialData.CredentialPublicKey,
            SignCount = attestationResult.Value.AuthenticatorData!.SignCount,
            Transports = publicKeyCredentialAttestation.Response.Transports?.Select(t => t.GetValue()).ToArray() ?? [],
        };

        await _credentialRepository.Add(credential);

        return AttestationCompleteResult.Create();
    }
}
