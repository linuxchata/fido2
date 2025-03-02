using System.Text;
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
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly ICredentialRepository _credentialRepository;
    private readonly Fido2Configuration _configuration;

    public Assertion(
        IClientDataHandler clientDataHandler,
        IChallengeGenerator challengeGenerator,
        ICredentialRepository credentialRepository,
        IOptions<Fido2Configuration> options)
    {
        _clientDataHandler = clientDataHandler;
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

    public Task<AssertionCompleteResult> Complete(
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
            return Task.FromResult(AssertionCompleteResult.CreateFailure("Assertion response cannot be null"));
        }

        // Step 5
        // If options.allowCredentials is not empty, verify that credential.id identifies one of the public key
        // credentials listed in options.allowCredentials.
        if (requestOptions.AllowCredentials?.Length != 0)
        {
            var credentialId = Encoding.ASCII.GetBytes(publicKeyCredentialAssertion.Id);
            if (!requestOptions.AllowCredentials!.Any(c => BytesArrayComparer.CompareNullable(c.Id, credentialId)))
            {
                return Task.FromResult(AssertionCompleteResult.CreateFailure(
                    "Assertion response does not contain expected credential identifier"));
            }
        }

        // Steps 9 to 14
        var challengeString = Convert.ToBase64String(requestOptions.Challenge);
        var clientDataHandlerResult = _clientDataHandler.HandleAssertion(response.ClientDataJson, challengeString);
        if (clientDataHandlerResult.HasError)
        {
            return Task.FromResult(AssertionCompleteResult.CreateFailure(clientDataHandlerResult.Message!));
        }

        return Task.FromResult(AssertionCompleteResult.Create());
    }
}
