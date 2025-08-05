using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// The interface representing the logic to define strategies for validating attestation statements.
/// </summary>
public interface IAttestationStatementStrategy
{
    /// <summary>
    /// Validates an attestation statement according to format-specific rules.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data.</param>
    /// <param name="clientData">The client data.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData);
}
