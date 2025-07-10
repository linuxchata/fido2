using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the TPM attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.3.
/// See: https://www.w3.org/TR/webauthn/#sctn-tpm-attestation.
/// </summary>
internal class TpmAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly ITpmtPublicAreaParserService _tpmtPublicAreaParserService;
    private readonly ITpmsAttestationParserService _tpmsAttestationParserService;
    private readonly IAttestationCertificateProviderService _attestationCertificateProviderService;
    private readonly ISignatureAttestationStatementValidator _signatureValidator;
    private readonly IAttestationCertificateValidator _attestationCertificateValidator;

    public TpmAttestationStatementStrategy(
        ITpmtPublicAreaParserService tpmtPublicAreaParserService,
        ITpmsAttestationParserService tpmsAttestationParserService,
        IAttestationCertificateProviderService certificateAttestationStatementProvider,
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        IAttestationCertificateValidator certificateAttestationStatementValidator)
    {
        _tpmtPublicAreaParserService = tpmtPublicAreaParserService;
        _tpmsAttestationParserService = tpmsAttestationParserService;
        _attestationCertificateProviderService = certificateAttestationStatementProvider;
        _signatureValidator = signatureAttestationStatementValidator;
        _attestationCertificateValidator = certificateAttestationStatementValidator;
    }

    /// <summary>
    /// Validates a TPM attestation statement.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the statement to validate.</param>
    /// <param name="clientData">The client data associated with the attestation.</param>
    /// <returns>A ValidatorInternalResult indicating whether the attestation statement is valid.</returns>
    /// <exception cref="ArgumentNullException">Thrown when attestationObjectData or clientData is null.</exception>
    /// <exception cref="ArgumentException">Thrown when attestation statement cannot be read.</exception>
    public ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectData);
        ArgumentNullException.ThrowIfNull(attestationObjectData.AttestationStatement);
        ArgumentNullException.ThrowIfNull(clientData);

        if (attestationObjectData.AttestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("TPM attestation statement cannot be read", nameof(attestationObjectData));
        }

        if (!attestationStatementDict.TryGetValue(AttestationStatement.PubArea, out var pubArea) ||
            pubArea is not byte[] ||
            !_tpmtPublicAreaParserService.Parse((byte[])pubArea, out TpmtPublic tpmtPublic))
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement pubArea cannot be read");
        }

        if (!attestationStatementDict.TryGetValue(AttestationStatement.CertInfo, out var certInfo) ||
            certInfo is not byte[] ||
            !_tpmsAttestationParserService.Parse((byte[])certInfo, out TpmsAttestation tpmsAttestation))
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement certInfo cannot be read");
        }

        // Verify that the public key specified by the parameters and unique fields of pubArea is identical
        // to the credentialPublicKey in the attestedCredentialData in authenticatorData.
        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;
        if (credentialPublicKey == null)
        {
            return ValidatorInternalResult.Invalid("Credential public key is not found");
        }

        if (tpmtPublic.EccParameters != null)
        {
            (var xCoordinate, var yCoordinate) = BytesArrayHelper.Split(tpmtPublic.Unique);

            if (!BytesArrayComparer.CompareNullable(credentialPublicKey.XCoordinate, xCoordinate))
            {
                return ValidatorInternalResult.Invalid("TPM attestation statement public key mismatch (X coordinate)");
            }

            if (!BytesArrayComparer.CompareNullable(credentialPublicKey.YCoordinate, yCoordinate))
            {
                return ValidatorInternalResult.Invalid("TPM attestation statement public key mismatch (Y coordinate)");
            }
        }
        else if (tpmtPublic.RsaParameters != null)
        {
            if (!BytesArrayComparer.CompareNullable(credentialPublicKey.Modulus, tpmtPublic.Unique))
            {
                return ValidatorInternalResult.Invalid("TPM attestation statement public key mismatch (modulus)");
            }

            if (GetExponentAsUInt32LittleEndian(credentialPublicKey.Exponent) != tpmtPublic.RsaParameters!.Exponent)
            {
                return ValidatorInternalResult.Invalid("TPM attestation statement public key mismatch (exponent)");
            }
        }

        // Validate that certInfo is valid
        // Verify that magic is set to TPM_GENERATED_VALUE.
        if (tpmsAttestation.Magic != TpmConstants.TpmGeneratedValue)
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement magic is invalid");
        }

        // Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        if (tpmsAttestation.Type != TpmConstants.TpmStAttestCertify)
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement type is invalid");
        }

        // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        if (!attestationStatementDict.TryGetValue(AttestationStatement.Algorithm, out var algorithm) ||
            algorithm is not int)
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement algorithm cannot be read");
        }

        if (!Enum.IsDefined(typeof(CoseAlgorithm), algorithm))
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement algorithm is not supported");
        }

        // Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        var attToBeSigned = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);
        var (keyType, hashAlgorithmName) = GenericKeyTypeMapper.Get((int)algorithm);
        var attToBeSignedHash = HashProvider.GetHash(attToBeSigned, hashAlgorithmName);
        if (!BytesArrayComparer.CompareNullable(attToBeSignedHash, tpmsAttestation.ExtraData))
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement extraData hash mismatch");
        }

        // Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2]
        // section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm
        // in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
        var pubAreaHash = HashProvider.GetHash((byte[])pubArea, TmpHashAlgorithmMapper.Get(tpmtPublic.NameAlg));
        if (!BytesArrayComparer.CompareNullable(pubAreaHash, tpmsAttestation.Attested.Name))
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement pubArea hash mismatch");
        }

        // Verify that x5c is present.
        if (!_attestationCertificateProviderService.AreCertificatesPresent(attestationStatementDict))
        {
            return ValidatorInternalResult.Invalid("TPM attestation statement certificates are not found");
        }

        // Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2,
        // i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an
        // input to risk engines.

        // Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with
        // the algorithm specified in alg.
        var certificates = _attestationCertificateProviderService.GetCertificates(attestationStatementDict);
        var attestationIdentityKeyCertificate = _attestationCertificateProviderService.GetAttestationCertificate(certificates);
        var result = _signatureValidator.ValidateTpm(
            (byte[])certInfo,
            attestationStatementDict,
            keyType,
            (int)algorithm,
            attestationIdentityKeyCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        // Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement Certificate Requirements.
        // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
        // the value of this extension matches the aaguid in authenticatorData.
        result = _attestationCertificateValidator.ValidateTpm(attestationIdentityKeyCertificate, attestationObjectData);
        if (!result.IsValid)
        {
            return result;
        }

        // If successful, return implementation-specific values representing attestation type AttCA and attestation
        // trust path x5c.
        return new AttestationStatementInternalResult(AttestationTypeEnum.AttCA, [.. certificates]);
    }

    private static uint GetExponentAsUInt32LittleEndian(byte[]? exponent)
    {
        if (exponent == null || exponent.Length == 0)
        {
            return uint.MinValue;
        }

        Array.Reverse(exponent);
        Array.Resize(ref exponent, 4);
        return BitConverter.ToUInt32(exponent, 0);
    }
}
