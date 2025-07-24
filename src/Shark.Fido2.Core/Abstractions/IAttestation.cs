using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions;

/// <summary>
/// Interface for handling FIDO2 attestations (registration).
/// Provides functionality for generating credential creation options and verifying registration responses.
/// </summary>
public interface IAttestation
{
    /// <summary>
    /// Generates credential creation options for a WebAuthn registration ceremony.
    /// </summary>
    /// <param name="request">The request containing parameters for generating credential creation options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>Credential creation options to be sent to the client.</returns>
    Task<PublicKeyCredentialCreationOptions> CreateOptions(
        PublicKeyCredentialCreationOptionsRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies an attestation from a client and completes the registration process.
    /// </summary>
    /// <param name="publicKeyCredentialAttestation">The credential attestation response received from the client.</param>
    /// <param name="creationOptions">The original creation options that were sent to the client.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The result of the attestation verification process.</returns>
    Task<AttestationCompleteResult> Complete(
        PublicKeyCredentialAttestation publicKeyCredentialAttestation,
        PublicKeyCredentialCreationOptions creationOptions,
        CancellationToken cancellationToken = default);
}
