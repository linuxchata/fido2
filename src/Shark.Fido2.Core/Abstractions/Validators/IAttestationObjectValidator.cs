using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// Validates the attestation object during WebAuthn registration ceremony.
/// </summary>
public interface IAttestationObjectValidator
{
    /// <summary>
    /// Validates the attestation object.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data to validate.</param>
    /// <param name="clientData">The client data associated with the registration ceremony.</param>
    /// <param name="creationOptions">The options that were used to create the credential.</param>
    /// <returns>A ValidatorInternalResult indicating whether the attestation object is valid.</returns>
    Task<ValidatorInternalResult> Validate(
        AttestationObjectData? attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions);
}
