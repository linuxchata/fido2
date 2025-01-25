﻿using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// None Attestation Statement Format
/// </summary>
internal class NoneAttestationStatementStategy : IAttestationStatementStategy
{
    public ValidatorInternalResult Validate(
        AttestationObjectData attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        return new AttestationStatementInternalResult(AttestationTypeEnum.None);
    }
}
