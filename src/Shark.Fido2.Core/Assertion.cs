using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core;

public sealed class Assertion : IAssertion
{
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly Fido2Configuration _configuration;

    public Assertion(
        IChallengeGenerator challengeGenerator,
        IOptions<Fido2Configuration> options)
    {
        _challengeGenerator = challengeGenerator;
        _configuration = options.Value;
    }

    public PublicKeyCredentialRequestOptions RequestOptions(PublicKeyCredentialRequestOptionsRequest request)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return new PublicKeyCredentialRequestOptions
        {
            Challenge = _challengeGenerator.Get(),
            Timeout = _configuration.Timeout,
            RpId = _configuration.RelyingPartyId,
            UserVerification = request.UserVerification ?? UserVerificationRequirement.Preferred,
        };
    }

    public Task<AssertionCompleteResult> Complete(
        PublicKeyCredentialAssertion publicKeyCredential,
        PublicKeyCredentialRequestOptions? requestOptions)
    {
        if (publicKeyCredential == null)
        {
            throw new ArgumentNullException(nameof(publicKeyCredential));
        }

        if (requestOptions == null)
        {
            throw new ArgumentNullException(nameof(requestOptions));
        }

        var response = publicKeyCredential.Response;
        if (response == null)
        {
            return Task.FromResult(AssertionCompleteResult.CreateFailure("Response cannot be null"));
        }

        return Task.FromResult(AssertionCompleteResult.Create());
    }
}
