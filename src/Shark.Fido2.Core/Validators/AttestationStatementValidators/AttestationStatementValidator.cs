using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

internal class AttestationStatementValidator : IAttestationStatementValidator
{
    private readonly IAttestationStatementStrategy _packedAttestationStatementStategy;
    private readonly IAttestationStatementStrategy _tmpAttestationStatementStrategy;
    private readonly IAttestationStatementStrategy _noneAttestationStatementStategy;

    public AttestationStatementValidator(
        [FromKeyedServices("packed")] IAttestationStatementStrategy packedAttestationStatementStategy,
        [FromKeyedServices("tpm")] IAttestationStatementStrategy tmpAttestationStatementStrategy,
        [FromKeyedServices("none")] IAttestationStatementStrategy noneAttestationStatementStategy)
    {
        _packedAttestationStatementStategy = packedAttestationStatementStategy;
        _tmpAttestationStatementStrategy = tmpAttestationStatementStrategy;
        _noneAttestationStatementStategy = noneAttestationStatementStategy;
    }

    public void Validate(
        AttestationObjectData attestationObjectData,
        AuthenticatorData authenticatorData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        if (attestationObjectData == null)
        {
            throw new ArgumentNullException(nameof(attestationObjectData));
        }

        var attestationStatementFormat = attestationObjectData.AttestationStatementFormat;

        if (string.IsNullOrEmpty(attestationStatementFormat))
        {
            throw new ArgumentNullException(nameof(attestationObjectData));
        }

        var strategyMap = new Dictionary<string, IAttestationStatementStrategy>
        {
            { AttestationStatementFormatIdentifier.Packed, _packedAttestationStatementStategy },
            { AttestationStatementFormatIdentifier.Tpm, _tmpAttestationStatementStrategy },
            { AttestationStatementFormatIdentifier.None, _noneAttestationStatementStategy },
        };

        var strategy = strategyMap.ContainsKey(attestationStatementFormat) ?
            strategyMap[attestationStatementFormat] :
            throw new ArgumentException($"{attestationStatementFormat} is not supported");

        strategy.Validate(attestationObjectData, clientData, creationOptions);
    }
}
