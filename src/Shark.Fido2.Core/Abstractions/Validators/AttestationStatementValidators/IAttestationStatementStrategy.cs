using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// Defines a strategy for validating FIDO2 attestation statements.
/// This interface is part of the strategy pattern that enables validation of different attestation statement formats
/// (e.g., Packed, TPM, Android Key, Android SafetyNet, FIDO U2F, Apple Anonymous, None).
/// </summary>
public interface IAttestationStatementStrategy
{
    /// <summary>
    /// Validates an attestation statement according to format-specific rules.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the statement to validate and authenticator data.</param>
    /// <param name="clientData">The client data containing the challenge and other contextual information.</param>
    /// <returns>A validation result indicating success or failure, and in case of success, the attestation type and trust path.</returns>
    ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData);
}
