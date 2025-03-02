using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions;

public interface IAssertion
{
    Task<PublicKeyCredentialRequestOptions> RequestOptions(PublicKeyCredentialRequestOptionsRequest request);

    Task<AssertionCompleteResult> Complete(
        PublicKeyCredentialAssertion publicKeyCredential,
        PublicKeyCredentialRequestOptions requestOptions);
}
