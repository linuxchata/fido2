using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface IAssertionParametersValidator
{
    void Validate(PublicKeyCredentialRequestOptionsRequest request);

    AssertionCompleteResult Validate(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions);
}
