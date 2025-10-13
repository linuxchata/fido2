using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate user handlers.
/// </summary>
public interface IUserHandlerValidator
{
    /// <summary>
    /// Validates that the user is the owner of the credential.
    /// </summary>
    /// <param name="credential">The credential.</param>
    /// <param name="assertion">The assertion.</param>
    /// <param name="requestOptions">The original request options.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(
        Credential credential,
        PublicKeyCredentialAssertion assertion,
        PublicKeyCredentialRequestOptions requestOptions);
}
