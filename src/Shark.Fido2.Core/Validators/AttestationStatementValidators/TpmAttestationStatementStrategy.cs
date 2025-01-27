using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// 8.3. TPM Attestation Statement Format
/// </summary>
internal class TpmAttestationStatementStrategy : IAttestationStatementStrategy
{
    private const string PubArea = "pubArea";

    private readonly ITpmtPublicParserService _tpmtPublicParserService;

    public TpmAttestationStatementStrategy(ITpmtPublicParserService tpmtPublicParserService)
    {
        _tpmtPublicParserService = tpmtPublicParserService;
    }

    public ValidatorInternalResult Validate(
        AttestationObjectData attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        var attestationStatement = attestationObjectData.AttestationStatement ??
            throw new ArgumentNullException(nameof(attestationObjectData));

        if (attestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("Attestation statement cannot be read", nameof(attestationObjectData));
        }

        if (!attestationStatementDict.TryGetValue(PubArea, out var pubArea) || pubArea is not byte[])
        {
            return ValidatorInternalResult.Invalid("Attestation statement pubArea cannot be read");
        }

        var tpmtPublic = _tpmtPublicParserService.Parse((byte[])pubArea);

        return new AttestationStatementInternalResult(AttestationTypeEnum.AttCA);
    }
}
