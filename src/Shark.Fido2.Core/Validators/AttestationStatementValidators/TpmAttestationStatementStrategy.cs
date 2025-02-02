using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Mappers;
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
    private readonly ISignatureAttestationStatementValidator _signatureValidator;

    public TpmAttestationStatementStrategy(
        ITpmtPublicAreaParserService tpmtPublicAreaParserService,
        ITpmsAttestationParserService tpmsAttestationParserService,
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        [FromKeyedServices("rsa")] ICryptographyValidator rsaCryptographyValidator,
        [FromKeyedServices("ec2")] ICryptographyValidator ec2CryptographyValidator,
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator)
    {
        _tpmtPublicAreaParserService = tpmtPublicAreaParserService;
        _tpmsAttestationParserService = tpmsAttestationParserService;
        _certificateProvider = certificateAttestationStatementProvider;
        _rsaCryptographyValidator = rsaCryptographyValidator;
        _ec2CryptographyValidator = ec2CryptographyValidator;
        _signatureValidator = signatureAttestationStatementValidator;
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
        if (!attestationStatementDict.TryGetValue(Algorithm, out var algorithm) || algorithm is not int)
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
        }

        if (!Enum.IsDefined(typeof(PublicKeyAlgorithm), algorithm))
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm is not supported");
        };

        var attToBeSigned = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);
        var hashAlgorithmName = GenericKeyTypeMapper.Get(credentialPublicKey.KeyType, (int)algorithm);
        var attToBeSignedHash = HashProvider.GetHash(attToBeSigned, hashAlgorithmName);
        if (!BytesArrayComparer.CompareNullable(attToBeSignedHash, tpmsAttestation.ExtraData))
        {
            return ValidatorInternalResult.Invalid("Attestation statement hash mismatch");
        }

        // Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2]
        // section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm
        // in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
        // TODO: Implement this check.

        // Verify that x5c is present.
        if (!_certificateProvider.AreCertificatesPresent(attestationStatementDict))
        {
            return ValidatorInternalResult.Invalid("Attestation statement certificates are not found");
        }

        // Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2,
        // i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an
        // input to risk engines.

        // Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with
        // the algorithm specified in alg.
        var certificates = _certificateProvider.GetCertificates(attestationStatementDict);
        var attestationIdentityKeyCertificate = _certificateProvider.GetAttestationCertificate(certificates);
        var result = _signatureValidator.Validate(
            (byte[])certInfo,
            attestationStatementDict,
            (KeyTypeEnum)credentialPublicKey.KeyType,
            (int)algorithm,
            attestationIdentityKeyCertificate);
        if (!result.IsValid)
        {
            return result;
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
