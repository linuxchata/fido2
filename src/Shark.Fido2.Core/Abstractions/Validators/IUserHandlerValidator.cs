using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// User handler validator.
/// </summary>
public interface IUserHandlerValidator
{
    /// <summary>
    /// Validates that the user is the owner of the credential.
    /// </summary>
    /// <param name="credential">The credential to validate against.</param>
    /// <param name="publicKeyCredentialAssertion">The assertion containing the user handle.</param>
    /// <param name="requestOptions">The request options containing allowCredentials and username.</param>
    /// <returns>A ValidatorInternalResult indicating whether the user handle is valid.</returns>
    ValidatorInternalResult Validate(
        Credential credential,
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions);
}
