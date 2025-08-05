using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate assertion parameters.
/// </summary>
public interface IAssertionParametersValidator
{
    /// <summary>
    /// Validates the assertion parameters provided in the request options request.
    /// </summary>
    /// <param name="request">The request containing parameters for generating credential request options.</param>
    void Validate(PublicKeyCredentialRequestOptionsRequest request);

    /// <summary>
    /// Validates the assertion response and request options.
    /// </summary>
    /// <param name="publicKeyCredentialAssertion">The credential assertion response.</param>
    /// <param name="requestOptions">The original request options.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    AssertionCompleteResult Validate(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions);
}
