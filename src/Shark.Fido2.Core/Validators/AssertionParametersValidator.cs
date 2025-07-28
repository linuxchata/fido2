using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Validators;

public sealed class AssertionParametersValidator : IAssertionParametersValidator
{
    private const int MaxUserNameLength = 64;

    public void Validate(PublicKeyCredentialRequestOptionsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.IsNullOrWhiteSpace(request.UserName) && request.UserName.Length > MaxUserNameLength)
        {
            throw new ArgumentException(
                $"Username cannot be more than {MaxUserNameLength} characters",
                nameof(request));
        }
    }

    public AssertionCompleteResult Validate(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialAssertion);
        ArgumentNullException.ThrowIfNull(requestOptions);

        if (!publicKeyCredentialAssertion.Id.IsBase64Url())
        {
            return AssertionCompleteResult.CreateFailure("Assertion identifier is not Base64URL-encoded");
        }

        if (!string.Equals(publicKeyCredentialAssertion.Type, PublicKeyCredentialType.PublicKey))
        {
            return AssertionCompleteResult.CreateFailure("Assertion type is not set to \"public-key\"");
        }

        return AssertionCompleteResult.Create();
    }
}
