using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core;

public sealed class Assertion : IAssertion
{
    private readonly IAssertionParametersValidator _assertionParametersValidator;
    private readonly IClientDataHandler _clientDataHandler;
    private readonly IAssertionObjectHandler _assertionObjectHandler;
    private readonly IUserHandlerValidator _userHandlerValidator;
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly ICredentialRepository _credentialRepository;
    private readonly Fido2Configuration _configuration;
    private readonly ILogger<Assertion> _logger;

    public Assertion(
        IAssertionParametersValidator assertionParametersValidator,
        IClientDataHandler clientDataHandler,
        IAssertionObjectHandler assertionObjectHandler,
        IUserHandlerValidator userHandlerValidator,
        IChallengeGenerator challengeGenerator,
        ICredentialRepository credentialRepository,
        IOptions<Fido2Configuration> options,
        ILogger<Assertion> logger)
    {
        _assertionParametersValidator = assertionParametersValidator;
        _clientDataHandler = clientDataHandler;
        _assertionObjectHandler = assertionObjectHandler;
        _userHandlerValidator = userHandlerValidator;
        _challengeGenerator = challengeGenerator;
        _credentialRepository = credentialRepository;
        _configuration = options.Value;
        _logger = logger;
    }

    public async Task<PublicKeyCredentialRequestOptions> BeginAuthentication(
        PublicKeyCredentialRequestOptionsRequest request,
        CancellationToken cancellationToken)
    {
        _assertionParametersValidator.Validate(request);

        var userName = request.UserName?.Trim();

        List<CredentialDescriptor>? credentials = null;
        if (!string.IsNullOrWhiteSpace(userName))
        {
            credentials = await _credentialRepository.Get(userName, cancellationToken);
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
            Username = userName,
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

        _logger.LogDebug("Request options are successfully constructed");

        return publicKeyCredentialRequestOptions;
    }

    public async Task<AssertionCompleteResult> CompleteAuthentication(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions,
        CancellationToken cancellationToken)
    {
        var validationResult = _assertionParametersValidator.Validate(
            publicKeyCredentialAssertion,
            requestOptions);
        if (!validationResult.IsValid)
        {
            return AssertionCompleteResult.CreateFailure(validationResult.Message!);
        }

        // 7.2. Verifying an Authentication Assertion

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
        if (IsCredentialNotAllowed(requestOptions, credentialId))
        {
            _logger.LogWarning(
                "Assertion response does not contain expected credential '{CredentialId}'",
                credentialId);
            return AssertionCompleteResult.CreateFailure(
                "Assertion response does not contain expected credential");
        }

        var credential = await _credentialRepository.Get(credentialId, cancellationToken);
        if (credential == null)
        {
            _logger.LogWarning("Registered credential '{CredentialId}' is not found", credentialId);
            return AssertionCompleteResult.CreateFailure("Registered credential is not found");
        }

        // Step 6
        // Identify the user being authenticated and verify that this user is the owner of the public key credential
        // source credentialSource identified by credential.id
        var result = _userHandlerValidator.Validate(credential, publicKeyCredentialAssertion, requestOptions);
        if (!result.IsValid)
        {
            _logger.LogWarning("User handler validator error: {Message}", result.Message!);
            return AssertionCompleteResult.CreateFailure(result.Message!);
        }

        // Step 7
        // Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your use case),
        // look up the corresponding credential public key and let credentialPublicKey be that credential public key.
        if (credential.CredentialPublicKey == null)
        {
            _logger.LogWarning("Registered credential's public key is not found");
            return AssertionCompleteResult.CreateFailure("Registered credential's public key is not found");
        }

        // Step 8
        // Let cData, authData and sig denote the value of response's clientDataJSON, authenticatorData, and
        // signature respectively.

        // Steps 9 to 14
        var challengeString = requestOptions.Challenge.ToBase64Url();
        var clientDataHandlerResult = _clientDataHandler.HandleAssertion(response.ClientDataJson, challengeString);
        if (clientDataHandlerResult.HasError)
        {
            _logger.LogWarning("Client data handler error: {Message}", clientDataHandlerResult.Message!);
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
            _logger.LogWarning("Assertion object handler error: {Message}", assertionResult.Message!);
            return AssertionCompleteResult.CreateFailure(assertionResult.Message!);
        }

        // Step 21
        // Let storedSignCount be the stored signature counter value associated with credential.id.
        // If authData.signCount is nonzero or storedSignCount is nonzero, then run the following sub-step:
        var signCount = assertionResult.Value!.SignCount;
        if (signCount != 0 || credential.SignCount != 0)
        {
            // If authData.signCount is greater than storedSignCount:
            if (signCount > credential.SignCount)
            {
                // Update storedSignCount to be the value of authData.signCount.
                await _credentialRepository.UpdateSignCount(credentialId, signCount, cancellationToken);
                _logger.LogDebug("Signature counter for credential '{CredentialId}' is updated", credentialId);
            }
            else
            {
                // Less than or equal to storedSignCount:
                // This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential
                // private key may exist and are being used in parallel. Relying Parties should incorporate this
                // information into their risk scoring. Whether the Relying Party updates storedSignCount in this case,
                // or not, or fails the authentication ceremony or not, is Relying Party-specific.
                var errorMessage = "The authenticator's signature counter value is less than or equal to the " +
                    "previously stored count, indicating that the device may have been cloned or duplicated.";
                _logger.LogWarning("{ErrorMessage}", errorMessage);
                return AssertionCompleteResult.CreateFailure(errorMessage);
            }
        }
        else
        {
            await _credentialRepository.UpdateLastUsedAt(credentialId, cancellationToken);
            _logger.LogDebug("Last used timestamp for credential '{CredentialId}' is updated", credentialId);
        }

        _logger.LogDebug("Assertion is successfully completed");

        return AssertionCompleteResult.Create();
    }

    private static bool IsCredentialNotAllowed(PublicKeyCredentialRequestOptions requestOptions, byte[] credentialId)
    {
        return requestOptions.AllowCredentials != null &&
            requestOptions.AllowCredentials.Length != 0 &&
            !Array.Exists(
                requestOptions.AllowCredentials,
                c => BytesArrayComparer.CompareNullable(c.Id, credentialId));
    }
}
