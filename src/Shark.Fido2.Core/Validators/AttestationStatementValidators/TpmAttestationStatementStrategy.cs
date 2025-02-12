﻿using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Constants;
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
    private readonly ITpmtPublicAreaParserService _tpmtPublicAreaParserService;
    private readonly ITpmsAttestationParserService _tpmsAttestationParserService;
    private readonly ICertificateAttestationStatementService _certificateProvider;
    private readonly ISignatureAttestationStatementValidator _signatureValidator;
    private readonly ICertificateAttestationStatementValidator _certificateValidator;

    public TpmAttestationStatementStrategy(
        ITpmtPublicAreaParserService tpmtPublicAreaParserService,
        ITpmsAttestationParserService tpmsAttestationParserService,
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        ICertificateAttestationStatementValidator certificateAttestationStatementValidator)
    {
        _tpmtPublicAreaParserService = tpmtPublicAreaParserService;
        _tpmsAttestationParserService = tpmsAttestationParserService;
        _certificateProvider = certificateAttestationStatementProvider;
        _signatureValidator = signatureAttestationStatementValidator;
        _certificateValidator = certificateAttestationStatementValidator;
    }

    public ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectData);
        ArgumentNullException.ThrowIfNull(attestationObjectData.AttestationStatement);
        ArgumentNullException.ThrowIfNull(clientData);

        if (attestationObjectData.AttestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("Attestation statement cannot be read", nameof(attestationObjectData));
        }

        if (!attestationStatementDict.TryGetValue(AttestationStatement.PubArea, out var pubArea) ||
            pubArea is not byte[] ||
            !_tpmtPublicAreaParserService.Parse((byte[])pubArea, out TpmtPublic tpmtPublic))
        {
            return ValidatorInternalResult.Invalid("Attestation statement pubArea cannot be read");
        }

        if (!attestationStatementDict.TryGetValue(AttestationStatement.CertInfo, out var certInfo) ||
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
            return ValidatorInternalResult.Invalid("Attestation statement public key mismatch (modulus)");
        }

        // TODO: How to validate EccParameters?

        if (GetExponentAsUInt32LittleEndian(credentialPublicKey.Exponent!) != tpmtPublic.RsaParameters!.Exponent)
        {
            return ValidatorInternalResult.Invalid("Attestation statement public key mismatch (exponent)");
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
        if (!attestationStatementDict.TryGetValue(AttestationStatement.Algorithm, out var algorithm) ||
            algorithm is not int)
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
        }

        if (!Enum.IsDefined(typeof(PublicKeyAlgorithm), algorithm))
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm is not supported");
        };

        // Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        var attToBeSigned = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);
        var hashAlgorithmName = GenericKeyTypeMapper.Get(credentialPublicKey.KeyType, (int)algorithm);
        var attToBeSignedHash = HashProvider.GetHash(attToBeSigned, hashAlgorithmName);
        if (!BytesArrayComparer.CompareNullable(attToBeSignedHash, tpmsAttestation.ExtraData))
        {
            return ValidatorInternalResult.Invalid("Attestation statement extraData hash mismatch");
        }

        // Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2]
        // section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm
        // in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
        var pubAreaHash = HashProvider.GetHash((byte[])pubArea, TmpHashAlgorithmMapper.Get(tpmtPublic.NameAlg));
        if (!BytesArrayComparer.CompareNullable(pubAreaHash, tpmsAttestation.Attested.Name))
        {
            return ValidatorInternalResult.Invalid("Attestation statement pubArea hash mismatch");
        }

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

        // Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement Certificate Requirements.
        // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
        // the value of this extension matches the aaguid in authenticatorData.
        result = _certificateValidator.ValidateTpm(attestationIdentityKeyCertificate, attestationObjectData);
        if (!result.IsValid)
        {
            return result;
        }

        // If successful, return implementation-specific values representing attestation type AttCA and attestation
        // trust path x5c.
        return new AttestationStatementInternalResult(AttestationTypeEnum.AttCA, [.. certificates]);
    }

    private static uint GetExponentAsUInt32LittleEndian(byte[] exponent)
    {
        Array.Reverse(exponent);
        Array.Resize(ref exponent, 4);
        return BitConverter.ToUInt32(exponent, 0);
    }
}
