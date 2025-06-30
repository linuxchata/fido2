using Microsoft.Extensions.Options;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core;

public sealed class Assertion : IAssertion
{
    private readonly IClientDataHandler _clientDataHandler;
    private readonly IAssertionObjectHandler _assertionObjectHandler;
    private readonly IUserHandlerValidator _userHandlerValidator;
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly ICredentialRepository _credentialRepository;
    private readonly Fido2Configuration _configuration;

    public Assertion(
        IClientDataHandler clientDataHandler,
        IAssertionObjectHandler assertionObjectHandler,
        IUserHandlerValidator userHandlerValidator,
        IChallengeGenerator challengeGenerator,
        ICredentialRepository credentialRepository,
        IOptions<Fido2Configuration> options)
    {
        _clientDataHandler = clientDataHandler;
        _assertionObjectHandler = assertionObjectHandler;
        _userHandlerValidator = userHandlerValidator;
        _challengeGenerator = challengeGenerator;
        _credentialRepository = credentialRepository;
        _configuration = options.Value;
    }

    public async Task<PublicKeyCredentialRequestOptions> RequestOptions(
        PublicKeyCredentialRequestOptionsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var username = request.Username?.Trim();

        List<CredentialDescriptor>? credentials = null;
        if (!string.IsNullOrWhiteSpace(username))
        {
            credentials = await _credentialRepository.Get(username, cancellationToken);
        }

        var appId = _configuration.AppId;

        var publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = _challengeGenerator.Get(),
            Timeout = _configuration.Timeout,
            RpId = _configuration.RelyingPartyId,
            AllowCredentials = credentials?
                .Select(c => new PublicKeyCredentialDescriptor
                {
                    Id = c.CredentialId,
                    Transports = c.Transports?.Select(t => t.ToEnum<AuthenticatorTransport>()).ToArray() ?? [],
                })
                .ToArray(),
            Username = username,
            UserVerification = request.UserVerification ?? UserVerificationRequirement.Preferred,
            Extensions = new AuthenticationExtensionsClientInputs
            {
                AppId = !string.IsNullOrWhiteSpace(appId) ? appId : null,
                UserVerificationMethod = _configuration.UseUserVerificationMethod,
                LargeBlob = _configuration.UseLargeBlob ?
                new AuthenticationExtensionsLargeBlobInputs
                {
                    Read = true,
                }
                : null,
            },
        };

        return publicKeyCredentialRequestOptions;
    }

    public async Task<AssertionCompleteResult> Complete(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialAssertion);
        ArgumentNullException.ThrowIfNull(requestOptions);

        //// 7.2. Verifying an Authentication Assertion

        if (!publicKeyCredentialAssertion.Id.IsBase64Url())
        {
            return AssertionCompleteResult.CreateFailure("Assertion identifier is not base64url encode");
        }

        if (!string.Equals(publicKeyCredentialAssertion.Type, PublicKeyCredentialType.PublicKey))
        {
            return AssertionCompleteResult.CreateFailure("Assertion type is not set to \"public-key\"");
        }

        // Step 3
        // Let response be credential.response. If response is not an instance of AuthenticatorAssertionResponse,
        // abort the ceremony with a user-visible error.
        var response = publicKeyCredentialAssertion.Response;
        if (response == null)
        {
            return AssertionCompleteResult.CreateFailure("Assertion response cannot be null");
        }

        // Step 5
        // If options.allowCredentials is not empty, verify that credential.id identifies one of the public key
        // credentials listed in options.allowCredentials.
        var credentialId = publicKeyCredentialAssertion.RawId.FromBase64Url();
        if (requestOptions.AllowCredentials != null && requestOptions.AllowCredentials.Length != 0)
        {
            if (!requestOptions.AllowCredentials.Any(c => BytesArrayComparer.CompareNullable(c.Id, credentialId)))
            {
                return AssertionCompleteResult.CreateFailure(
                    "Assertion response does not contain expected credential identifier");
            }
        }

        var credential = await _credentialRepository.Get(credentialId, cancellationToken);
        if (credential == null)
        {
            return AssertionCompleteResult.CreateFailure("Registered credential is not found");
        }

        // Step 6
        // Identify the user being authenticated and verify that this user is the owner of the public key credential
        // source credentialSource identified by credential.id
        var result = _userHandlerValidator.Validate(credential, publicKeyCredentialAssertion, requestOptions);
        if (!result.IsValid)
        {
            return AssertionCompleteResult.CreateFailure(result.Message!);
        }

        // Step 7
        // Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your use case),
        // look up the corresponding credential public key and let credentialPublicKey be that credential public key.
        if (credential.CredentialPublicKey == null)
        {
            return AssertionCompleteResult.CreateFailure("Registered credential's credential public key is not found");
        }

        // Step 8
        // Let cData, authData and sig denote the value of response's clientDataJSON, authenticatorData, and
        // signature respectively.

        // Steps 9 to 14
        var challengeString = requestOptions.Challenge.ToBase64Url();
        var clientDataHandlerResult = _clientDataHandler.HandleAssertion(response.ClientDataJson, challengeString);
        if (clientDataHandlerResult.HasError)
        {
            return AssertionCompleteResult.CreateFailure(clientDataHandlerResult.Message!);
        }

        // Steps 15 to 20
        var assertionResult = _assertionObjectHandler.Handle(
            publicKeyCredentialAssertion.Response.AuthenticatorData,
            publicKeyCredentialAssertion.Response.Signature,
            clientDataHandlerResult.Value!,
            credential.CredentialPublicKey,
            publicKeyCredentialAssertion.Extensions,
            requestOptions);
        if (assertionResult.HasError)
        {
            // Step 22
            // If all the above steps are successful, continue with the authentication ceremony as appropriate.
            // Otherwise, fail the authentication ceremony.
            return AssertionCompleteResult.CreateFailure(assertionResult.Message!);
        }

        // Step 21
        // Let storedSignCount be the stored signature counter value associated with credential.id.
        // If authData.signCount is nonzero or storedSignCount is nonzero, then run the following sub-step:
        if (assertionResult.Value!.SignCount != 0 || credential.SignCount != 0)
        {
            // If authData.signCount is greater than storedSignCount:
            if (assertionResult.Value!.SignCount > credential.SignCount)
            {
                // Update storedSignCount to be the value of authData.signCount.
                await _credentialRepository.UpdateSignCount(
                    credential.CredentialId,
                    assertionResult.Value!.SignCount,
                    cancellationToken);
            }
            else
            {
                // Less than or equal to storedSignCount:
                // This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential
                // private key may exist and are being used in parallel. Relying Parties should incorporate this
                // information into their risk scoring. Whether the Relying Party updates storedSignCount in this case,
                // or not, or fails the authentication ceremony or not, is Relying Party-specific.
                return AssertionCompleteResult.CreateFailure(
                    "Signature counter of the authenticator is less or equal to stored signature count. " +
                    "The authenticator may be cloned");
            }
        }
        else
        {
            await _credentialRepository.UpdateLastUsedAt(credential.CredentialId, cancellationToken);
        }

        return AssertionCompleteResult.Create();
    }
}
