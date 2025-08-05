using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Handlers;

/// <summary>
/// The interface representing the logic to handle attestation objects during a registration.
/// </summary>
public interface IAttestationObjectHandler
{
    /// <summary>
    /// Handles the processing of an attestation object from a registration response.
    /// </summary>
    /// <param name="attestationObject">The attestation object.</param>
    /// <param name="clientData">The parsed client data.</param>
    /// <param name="creationOptions">The original creation options.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    Task<InternalResult<AttestationObjectData>> Handle(
        string attestationObject,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions);
}
