using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Enums;
using Shark.Fido2.Core.Helpers;
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
    private const string Algorithm = "alg";

    private readonly ITpmtPublicAreaParserService _tpmtPublicAreaParserService;
    private readonly ITpmsAttestationParserService _tpmsAttestationParserService;
    private readonly ICertificateAttestationStatementService _certificateProvider;
    private readonly ICryptographyValidator _rsaCryptographyValidator;
    private readonly ICryptographyValidator _ec2CryptographyValidator;

    public TpmAttestationStatementStrategy(
        ITpmtPublicAreaParserService tpmtPublicAreaParserService,
        ITpmsAttestationParserService tpmsAttestationParserService,
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        [FromKeyedServices("rsa")] ICryptographyValidator rsaCryptographyValidator,
        [FromKeyedServices("ec2")] ICryptographyValidator ec2CryptographyValidator)
    {
        _tpmtPublicAreaParserService = tpmtPublicAreaParserService;
        _tpmsAttestationParserService = tpmsAttestationParserService;
        _certificateProvider = certificateAttestationStatementProvider;
        _rsaCryptographyValidator = rsaCryptographyValidator;
        _ec2CryptographyValidator = ec2CryptographyValidator;
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

        // Validate that certInfo is valid
        // Verify that magic is set to TPM_GENERATED_VALUE.
        if (tpmsAttestation.Magic != 0xff544347)
        {
            return ValidatorInternalResult.Invalid("Attestation statement magic is invalid");
        }

        // Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        if (tpmsAttestation.Type != 0x8017)
        {
            return ValidatorInternalResult.Invalid("Attestation statement type is invalid");
        }

        // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        var attToBeSigned = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);

        if (!attestationStatementDict.TryGetValue(Algorithm, out var algorithm) || algorithm is not int)
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
        }

        var certificates = _certificateProvider.GetCertificates(attestationStatementDict);
        var attestationCertificate = _certificateProvider.GetAttestationCertificate(certificates);

        bool isValid;
        if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Rsa)
        {
            isValid = _rsaCryptographyValidator.IsValid(
                attToBeSigned,
                tpmsAttestation.ExtraData,
                attestationCertificate,
                credentialPublicKey);
        }
        else if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Ec2)
        {
            isValid = _ec2CryptographyValidator.IsValid(
                attToBeSigned,
                tpmsAttestation.ExtraData,
                attestationCertificate,
                credentialPublicKey);
        }
        else
        {
            throw new NotSupportedException("Unsupported key type");
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
