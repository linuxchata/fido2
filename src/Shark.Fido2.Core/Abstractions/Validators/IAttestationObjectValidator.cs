using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate attestation objects.
/// </summary>
public interface IAttestationObjectValidator
{
    /// <summary>
    /// Validates an attestation object.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data.</param>
    /// <param name="clientData">The client data.</param>
    /// <param name="creationOptions">The original creation options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    Task<ValidatorInternalResult> Validate(
        AttestationObjectData? attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions,
        CancellationToken cancellationToken);
}
