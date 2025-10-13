using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions;

/// <summary>
/// The interface representing the logic to handle assertions (authentication).
/// </summary>
public interface IAssertion
{
    /// <summary>
    /// Generates credential request options.
    /// </summary>
    /// <param name="request">The request containing parameters for generating credential request options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>Credential request options.</returns>
    Task<PublicKeyCredentialRequestOptions> BeginAuthentication(
        PublicKeyCredentialRequestOptionsRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Verifies an assertion from a client and completes the authentication process.
    /// </summary>
    /// <param name="assertion">The credential assertion response.</param>
    /// <param name="requestOptions">The original request options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The result of the assertion verification process.</returns>
    Task<AssertionCompleteResult> CompleteAuthentication(
        PublicKeyCredentialAssertion assertion,
        PublicKeyCredentialRequestOptions requestOptions,
        CancellationToken cancellationToken);
}
