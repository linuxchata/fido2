using Microsoft.Extensions.Options;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core;

public sealed class Assertion : IAssertion
{
    private readonly IClientDataHandler _clientDataHandler;
    private readonly IAssertionObjectHandler _assertionObjectHandler;
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly ICredentialRepository _credentialRepository;
    private readonly Fido2Configuration _configuration;

    public Assertion(
        IClientDataHandler clientDataHandler,
        IAssertionObjectHandler assertionObjectHandler,
        IChallengeGenerator challengeGenerator,
        ICredentialRepository credentialRepository,
        IOptions<Fido2Configuration> options)
    {
        _clientDataHandler = clientDataHandler;
        _assertionObjectHandler = assertionObjectHandler;
        _challengeGenerator = challengeGenerator;
        _credentialRepository = credentialRepository;
        _configuration = options.Value;
    }

    public async Task<PublicKeyCredentialRequestOptions> RequestOptions(
        PublicKeyCredentialRequestOptionsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var credentials = await _credentialRepository.Get(request.Username);

        return new PublicKeyCredentialRequestOptions
        {
            Challenge = _challengeGenerator.Get(),
            Timeout = _configuration.Timeout,
            RpId = _configuration.RelyingPartyId,
            AllowCredentials = credentials.Select(c => new PublicKeyCredentialDescriptor
            {
                Id = c.CredentialId,
                Transports = c.Transports?.Select(t => t.ToEnum<AuthenticatorTransport>()).ToArray() ?? [],
            }).ToArray(),
            UserVerification = request.UserVerification ?? UserVerificationRequirement.Preferred,
        };
    }

    public async Task<AssertionCompleteResult> Complete(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialAssertion);
        ArgumentNullException.ThrowIfNull(requestOptions);

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
        var credentialId = Convert.FromBase64String(publicKeyCredentialAssertion.RawId);
        if (requestOptions.AllowCredentials != null && requestOptions.AllowCredentials.Length != 0)
        {
            if (!requestOptions.AllowCredentials!.Any(c => BytesArrayComparer.CompareNullable(c.Id, credentialId)))
            {
                return AssertionCompleteResult.CreateFailure(
                    "Assertion response does not contain expected credential identifier");
            }
        }

        // Steps 9 to 14
        var challengeString = Convert.ToBase64String(requestOptions.Challenge);
        var clientDataHandlerResult = _clientDataHandler.HandleAssertion(response.ClientDataJson, challengeString);
        if (clientDataHandlerResult.HasError)
        {
            return AssertionCompleteResult.CreateFailure(clientDataHandlerResult.Message!);
        }

        // Steps 15 to 18
        var credential = await _credentialRepository.Get(credentialId);
        if (credential == null)
        {
            return AssertionCompleteResult.CreateFailure("Registered credential was not found");
        }

        var assertionResult = _assertionObjectHandler.Handle(
            publicKeyCredentialAssertion.Response.AuthenticatorData,
            publicKeyCredentialAssertion.Response.Signature,
            clientDataHandlerResult.Value!,
            credential.CredentialPublicKey,
            requestOptions);

        return AssertionCompleteResult.Create();
    }
}
