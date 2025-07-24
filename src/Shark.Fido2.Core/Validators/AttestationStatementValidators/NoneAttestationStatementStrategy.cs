using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the None attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.7.
/// See: https://www.w3.org/TR/webauthn/#sctn-none-attestation.
/// </summary>
internal class NoneAttestationStatementStrategy : IAttestationStatementStrategy
{
    /// <summary>
    /// Validates a None attestation statement.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the statement to validate.</param>
    /// <param name="clientData">The client data associated with the attestation.</param>
    /// <returns>A ValidatorInternalResult indicating whether the attestation statement is valid.</returns>
    public ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        if (attestationObjectData.AttestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("None attestation statement cannot be read", nameof(attestationObjectData));
        }

        if (attestationStatementDict.Count > 0)
        {
            return ValidatorInternalResult.Invalid("None attestation statement is not empty");
        }

        return new AttestationStatementInternalResult(AttestationStatementFormatIdentifier.None, AttestationType.None);
    }
}
