using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions;

/// <summary>
/// The interface representing the logic to handle attestations (registration).
/// </summary>
public interface IAttestation
{
    /// <summary>
    /// Generates credential creation options.
    /// </summary>
    /// <param name="request">The request containing parameters for generating credential creation options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>Credential creation options.</returns>
    Task<PublicKeyCredentialCreationOptions> BeginRegistration(
        PublicKeyCredentialCreationOptionsRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Verifies an attestation from a client and completes the registration process.
    /// </summary>
    /// <param name="publicKeyCredentialAttestation">The credential attestation response.</param>
    /// <param name="creationOptions">The original creation options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The result of the attestation verification process.</returns>
    Task<AttestationCompleteResult> CompleteRegistration(
        PublicKeyCredentialAttestation publicKeyCredentialAttestation,
        PublicKeyCredentialCreationOptions creationOptions,
        CancellationToken cancellationToken);
}
