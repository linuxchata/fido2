using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions;

/// <summary>
/// Interface for handling FIDO2 assertions (authentication).
/// Provides functionality for generating credential request options and verifying authentication responses.
/// </summary>
public interface IAssertion
{
    /// <summary>
    /// Generates credential request options for a WebAuthn authentication ceremony.
    /// </summary>
    /// <param name="request">The request containing parameters for generating credential request options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>Credential request options to be sent to the client.</returns>
    Task<PublicKeyCredentialRequestOptions> BeginAuthentication(
        PublicKeyCredentialRequestOptionsRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies an assertion from a client.
    /// </summary>
    /// <param name="publicKeyCredentialAssertion">The credential assertion response received from the client.</param>
    /// <param name="requestOptions">The original request options that were sent to the client.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The result of the assertion verification process.</returns>
    Task<AssertionCompleteResult> CompleteAuthentication(
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions,
        CancellationToken cancellationToken = default);
}
