﻿using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// 8.5. Android SafetyNet Attestation Statement Format
/// </summary>
internal class AndroidSafetyNetAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly IJwsResponseParserService _jwsParserService;
    private readonly ICertificateAttestationStatementService _certificateProvider;
    private readonly ICertificateAttestationStatementValidator _certificateValidator;

    public AndroidSafetyNetAttestationStatementStrategy(
        IJwsResponseParserService jwsParserService,
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        ICertificateAttestationStatementValidator certificateAttestationStatementValidator)
    {
        _jwsParserService = jwsParserService;
        _certificateProvider = certificateAttestationStatementProvider;
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

        // Verify that response is a valid SafetyNet response of version ver by following the steps indicated by the
        // SafetyNet online documentation. As of this writing, there is only one format of the SafetyNet response and
        // ver is reserved for future use.
        if (!attestationStatementDict.TryGetValue(AttestationStatement.Version, out var version) ||
            version is not string)
        {
            return ValidatorInternalResult.Invalid("Attestation statement ver cannot be read");
        }

        if (!attestationStatementDict.TryGetValue(AttestationStatement.Response, out var response) ||
            response is not byte[])
        {
            return ValidatorInternalResult.Invalid("Attestation statement response cannot be read");
        }

        var jwsResposne = _jwsParserService.Parse((byte[])response);
        if (jwsResposne == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement JWS response cannot be read");
        }

        // Verify that the nonce attribute in the payload of response is identical to the Base64 encoding of the
        // SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
        if (jwsResposne.Nonce == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement JWS response nonce is not found");
        }

        var concatenatedData = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);
        var concatenatedDataHash = HashProvider.GetHash(concatenatedData, HashAlgorithmName.SHA256);

        var nonceHash = HashProvider.GetHash(Convert.FromBase64String(jwsResposne.Nonce), HashAlgorithmName.SHA256);

        if (!BytesArrayComparer.CompareNullable(nonceHash, concatenatedDataHash))
        {
            return ValidatorInternalResult.Invalid(
                "Attestation statement JWS response nonce is not identical to the concatenation of authenticatorData and clientDataHash");
        }

        // Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the
        // SafetyNet online documentation.
        // https://web.archive.org/web/20180710064905/https://developer.android.com/training/safetynet/attestation#verify-compat-check
        if (jwsResposne.CtsProfileMatch == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement JWS response ctsProfileMatch is not found");
        }

        if (jwsResposne.BasicIntegrity == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement JWS response basicIntegrity is not found");
        }

        if (string.IsNullOrWhiteSpace(jwsResposne.ApkPackageName) ||
            string.IsNullOrWhiteSpace(jwsResposne.ApkCertificateDigestSha256) ||
            string.IsNullOrWhiteSpace(jwsResposne.ApkDigestSha256))
        {
            return ValidatorInternalResult.Invalid("Attestation statement JWS response APK information is not found");
        }

        // If successful, return implementation-specific values representing attestation type Basic and attestation
        // trust path x5c.
        if (jwsResposne.Certificates == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement JWS response certificates are not found");
        }

        var certificates = _certificateProvider.GetCertificates(jwsResposne.Certificates);

        // Validate the SSL certificate chain
        // TODO: Skip result of SSL certificate chain validation, since provided certificates are not valid. 
        _certificateValidator.ValidateChainOfTrustWithSystemCa(certificates);

        // Use SSL hostname matching to verify that the leaf certificate was issued to the hostname attest.android.com
        var attestationCertificate = _certificateProvider.GetAttestationCertificate(certificates);
        var result = _certificateValidator.ValidateAndroidSafetyNet(attestationCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        return new AttestationStatementInternalResult(AttestationTypeEnum.Basic, [.. certificates]);
    }
}
