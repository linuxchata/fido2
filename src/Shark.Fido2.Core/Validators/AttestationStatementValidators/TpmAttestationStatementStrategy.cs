using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// 8.3. TPM Attestation Statement Format
/// </summary>
internal class TpmAttestationStatementStrategy : IAttestationStatementStrategy
{
    private const string PubArea = "pubArea";
    private const string CertInfo = "certInfo";

    private readonly ITpmtPublicAreaParserService _tpmtPublicAreaParserService;
    private readonly ITpmsAttestationParserService _tpmsAttestationParserService;

    public TpmAttestationStatementStrategy(
        ITpmtPublicAreaParserService tpmtPublicAreaParserService,
        ITpmsAttestationParserService tpmsAttestationParserService)
    {
        _tpmtPublicAreaParserService = tpmtPublicAreaParserService;
        _tpmsAttestationParserService = tpmsAttestationParserService;
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

        if (!attestationStatementDict.TryGetValue(PubArea, out var pubArea) ||
            pubArea is not byte[] ||
            !_tpmtPublicAreaParserService.Parse((byte[])pubArea, out TpmtPublic tpmtPublic))
        {
            return ValidatorInternalResult.Invalid("Attestation statement pubArea cannot be read");
        }

        if (!attestationStatementDict.TryGetValue(CertInfo, out var certInfo) ||
            certInfo is not byte[] ||
            !_tpmsAttestationParserService.Parse((byte[])certInfo, out TpmsAttestation tpmsAttestation))
        {
            return ValidatorInternalResult.Invalid("Attestation statement certInfo cannot be read");
        }

        // Verify that the public key specified by the parameters and unique fields of pubArea is identical
        // to the credentialPublicKey in the attestedCredentialData in authenticatorData.
        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;
        if (!BytesArrayComparer.CompareNullable(credentialPublicKey.Modulus, tpmtPublic.Unique))
        {
            return ValidatorInternalResult.Invalid("Attestation statement public key mismatch");
        }

        if (GetExponentAsUInt32LittleEndian(credentialPublicKey.Exponent!) != tpmtPublic.RsaParameters!.Exponent)
        {
            return ValidatorInternalResult.Invalid("Attestation statement public key mismatch");
        }

        return new AttestationStatementInternalResult(AttestationTypeEnum.AttCA);
    }

    private static uint GetExponentAsUInt32LittleEndian(byte[] exponent)
    {
        Array.Reverse(exponent);
        Array.Resize(ref exponent, 4);
        return BitConverter.ToUInt32(exponent, 0);
    }
}
