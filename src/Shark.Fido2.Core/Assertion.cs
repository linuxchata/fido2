using Microsoft.Extensions.Options;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core;

public sealed class Assertion : IAssertion
{
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly ICredentialRepository _credentialRepository;
    private readonly Fido2Configuration _configuration;

    public Assertion(
        IChallengeGenerator challengeGenerator,
        ICredentialRepository credentialRepository,
        IOptions<Fido2Configuration> options)
    {
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
        PublicKeyCredentialAssertion publicKeyCredential,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredential);
        ArgumentNullException.ThrowIfNull(requestOptions);

        var response = publicKeyCredential.Response;
        if (response == null)
        {
            return Task.FromResult(AssertionCompleteResult.CreateFailure("Response cannot be null"));
        }

        return Task.FromResult(AssertionCompleteResult.Create());
    }
}
