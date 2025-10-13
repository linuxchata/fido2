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
        PublicKeyCredentialAssertion assertion,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(requestOptions);

        if (!assertion.Id.IsBase64Url())
        {
            return AssertionCompleteResult.CreateFailure("Assertion identifier is not Base64URL-encoded");
        }

        if (!string.Equals(assertion.Type, PublicKeyCredentialType.PublicKey))
        {
            return AssertionCompleteResult.CreateFailure("Assertion type is not set to \"public-key\"");
        }

        return AssertionCompleteResult.Create();
    }
}
