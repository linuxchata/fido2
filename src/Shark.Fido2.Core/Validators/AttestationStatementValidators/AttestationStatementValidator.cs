﻿using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

internal class AttestationStatementValidator : IAttestationStatementValidator
{
    private readonly Dictionary<string, IAttestationStatementStrategy> _strategiesMap;

    public AttestationStatementValidator(
        [FromKeyedServices(AttestationStatementFormatIdentifier.Packed)]
        IAttestationStatementStrategy packedAttestationStatementStategy,
        [FromKeyedServices(AttestationStatementFormatIdentifier.Tpm)]
        IAttestationStatementStrategy tpmAttestationStatementStrategy,
        [FromKeyedServices(AttestationStatementFormatIdentifier.AndroidKey)]
        IAttestationStatementStrategy androidKeyAttestationStatementStrategy,
        [FromKeyedServices(AttestationStatementFormatIdentifier.AndroidSafetyNet)]
        IAttestationStatementStrategy androidSafetyNetAttestationStatementStrategy,
        [FromKeyedServices(AttestationStatementFormatIdentifier.FidoU2f)]
        IAttestationStatementStrategy fidoU2fAttestationStatementStrategy,
        [FromKeyedServices(AttestationStatementFormatIdentifier.None)]
        IAttestationStatementStrategy noneAttestationStatementStategy,
        [FromKeyedServices(AttestationStatementFormatIdentifier.Apple)]
        IAttestationStatementStrategy appleAnonymousAttestationStatementStrategy)
    {
        _strategiesMap = new Dictionary<string, IAttestationStatementStrategy>
        {
            { AttestationStatementFormatIdentifier.Packed, packedAttestationStatementStategy },
            { AttestationStatementFormatIdentifier.Tpm, tpmAttestationStatementStrategy },
            { AttestationStatementFormatIdentifier.AndroidKey, androidKeyAttestationStatementStrategy },
            { AttestationStatementFormatIdentifier.AndroidSafetyNet, androidSafetyNetAttestationStatementStrategy },
            { AttestationStatementFormatIdentifier.FidoU2f, fidoU2fAttestationStatementStrategy },
            { AttestationStatementFormatIdentifier.None, noneAttestationStatementStategy },
            { AttestationStatementFormatIdentifier.Apple, appleAnonymousAttestationStatementStrategy },
        };
    }

    public void Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectData);
        ArgumentNullException.ThrowIfNull(clientData);

        var attestationStatementFormat = attestationObjectData.AttestationStatementFormat;

        if (string.IsNullOrEmpty(attestationStatementFormat))
        {
            throw new ArgumentNullException(nameof(attestationObjectData));
        }

        if (!_strategiesMap.TryGetValue(attestationStatementFormat, out IAttestationStatementStrategy? strategy))
        {
            throw new ArgumentException($"{attestationStatementFormat} is not supported");
        }

        strategy.Validate(attestationObjectData, clientData);
    }
}
