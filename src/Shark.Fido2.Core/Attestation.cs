using Microsoft.Extensions.Options;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
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

    public async Task<PublicKeyCredentialCreationOptions> GetOptions(
        PublicKeyCredentialCreationOptionsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var username = request.Username.Trim();

        var credentials = await _credentialRepository.Get(username, cancellationToken);
        PublicKeyCredentialDescriptor[]? excludeCredentials = null;
        if (credentials != null && credentials.Count > 0)
        {
            excludeCredentials = credentials
                .Select(c => new PublicKeyCredentialDescriptor
                {
                    Id = c.CredentialId,
                    Transports = c.Transports?.Select(t => t.ToEnum<AuthenticatorTransport>()).ToArray() ?? [],
                    Type = PublicKeyCredentialType.PublicKey,
                })
                .ToArray();
        }

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions
        {
            RelyingParty = new PublicKeyCredentialRpEntity
            {
                Id = _configuration.RelyingPartyId,
                Name = _configuration.RelyingPartyIdName,
            },
            User = new PublicKeyCredentialUserEntity
            {
                Id = username.FromBase64Url(),
                Name = username,
                DisplayName = request.DisplayName.Trim(),
            },
            Challenge = _challengeGenerator.Get(),
            PublicKeyCredentialParams = PublicKeyAlgorithms.Extended
                .Select(a => new PublicKeyCredentialParameter { Algorithm = a })
                .ToArray(),
            Timeout = _configuration.Timeout ?? DefaultTimeout,
            ExcludeCredentials = excludeCredentials ?? [],
            AuthenticatorSelection = GetAuthenticatorSelection(request),
            Attestation = GetAttestation(request.Attestation),
            Extensions = new AuthenticationExtensionsClientInputs
            {
                UserVerificationMethod = true,
                CredentialProperties = true,
            },
        };

        return credentialCreationOptions;
    }

    public async Task<AttestationCompleteResult> Complete(
        PublicKeyCredentialAttestation publicKeyCredentialAttestation,
        PublicKeyCredentialCreationOptions creationOptions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialAttestation);
        ArgumentNullException.ThrowIfNull(creationOptions);

        //// 7.1. Registering a New Credential

        if (!publicKeyCredentialAttestation.Id.IsBase64Url())
        {
            return AttestationCompleteResult.CreateFailure("Attestation identifier is not base64url encode");
        }

        if (!string.Equals(publicKeyCredentialAttestation.Type, PublicKeyCredentialType.PublicKey))
        {
            return AttestationCompleteResult.CreateFailure("Attestation type is not set to \"public-key\"");
        }

        // Step 3
        // Let response be credential.response. If response is not an instance of AuthenticatorAttestationResponse,
        // abort the ceremony with a user-visible error.
        var response = publicKeyCredentialAttestation.Response;
        if (response == null)
        {
            return AttestationCompleteResult.CreateFailure("Attestation response cannot be null");
        }

        // Steps 5 to 12
        var challengeString = creationOptions.Challenge.ToBase64Url();
        var clientDataHandlerResult = _clientDataHandler.HandleAttestation(response.ClientDataJson, challengeString);
        if (clientDataHandlerResult.HasError)
        {
            return AttestationCompleteResult.CreateFailure(clientDataHandlerResult.Message!);
        }

        // Steps 13 to 21
        var attestationResult = await _attestationObjectHandler.Handle(
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
        var credential = await _credentialRepository.Get(credentialId, cancellationToken);
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
            CredentialPublicKey = attestedCredentialData.CredentialPublicKey!,
            SignCount = attestationResult.Value.AuthenticatorData!.SignCount,
            Transports = publicKeyCredentialAttestation.Response.Transports?.Select(t => t.GetValue()).ToArray() ?? [],
        };

        await _credentialRepository.Add(credential, cancellationToken);

        return AttestationCompleteResult.Create();
    }

    private static AuthenticatorSelectionCriteria GetAuthenticatorSelection(
        PublicKeyCredentialCreationOptionsRequest request)
    {
        return request.AuthenticatorSelection != null ?
            new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = request.AuthenticatorSelection.AuthenticatorAttachment,
                ResidentKey = request.AuthenticatorSelection.ResidentKey,
                RequireResidentKey = request.AuthenticatorSelection.ResidentKey == ResidentKeyRequirement.Required,
                UserVerification = request.AuthenticatorSelection.UserVerification ??
                    UserVerificationRequirement.Preferred,
            }
            : new AuthenticatorSelectionCriteria
            {
                ResidentKey = ResidentKeyRequirement.Discouraged,
                RequireResidentKey = false,
                UserVerification = UserVerificationRequirement.Preferred,
            };
    }

    private static string GetAttestation(string? attestation)
    {
        if (attestation == null)
        {
            return AttestationConveyancePreference.None;
        }

        return AttestationConveyancePreference.Supported.Contains(attestation) ?
            attestation : AttestationConveyancePreference.None;
    }
}
