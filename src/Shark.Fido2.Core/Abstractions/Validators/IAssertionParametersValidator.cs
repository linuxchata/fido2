using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// Defines methods for validating assertion parameters during WebAuthn authentication.
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
    /// <param name="publicKeyCredentialAssertion">The credential assertion response received from the client.</param>
    /// <param name="requestOptions">The original request options that were sent to the client.</param>
    /// <returns>An <see cref="AssertionCompleteResult"/> indicating the outcome of the validation.</returns>
    AssertionCompleteResult Validate(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions);
}
