﻿using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the None attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.7.
/// See: https://www.w3.org/TR/webauthn/#sctn-none-attestation
/// </summary>
internal class NoneAttestationStatementStrategy : IAttestationStatementStrategy
{
    /// <summary>
    /// Validates a None attestation statement.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the statement to validate</param>
    /// <param name="clientData">The client data associated with the attestation</param>
    /// <returns>A ValidatorInternalResult indicating whether the attestation statement is valid</returns>
    public ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        return new AttestationStatementInternalResult(AttestationTypeEnum.None);
    }
}
