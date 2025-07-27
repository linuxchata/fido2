using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Validators;

public sealed class AssertionParametersValidator : IAssertionParametersValidator
{
    public void Validate(PublicKeyCredentialRequestOptionsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
    }

    public void Validate(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialAssertion);
        ArgumentNullException.ThrowIfNull(requestOptions);
    }
}
