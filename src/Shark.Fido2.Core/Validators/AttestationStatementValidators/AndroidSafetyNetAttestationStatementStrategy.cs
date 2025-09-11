using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the Android SafetyNet attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.5.
/// See: https://www.w3.org/TR/webauthn/#sctn-android-safetynet-attestation.
/// </summary>
internal class AndroidSafetyNetAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly IAndroidSafetyNetJwsResponseParserService _jwsResponseParserService;
    private readonly IAndroidSafetyNetJwsResponseValidator _jwsResponseValidator;
    private readonly IAttestationCertificateProviderService _attestationCertificateProviderService;
    private readonly IAttestationCertificateValidator _attestationCertificateValidator;

    public AndroidSafetyNetAttestationStatementStrategy(
        IAndroidSafetyNetJwsResponseParserService androidSafetyNetJwsResponseParserService,
        IAndroidSafetyNetJwsResponseValidator androidSafetyNetJwsResponseValidator,
        IAttestationCertificateProviderService attestationCertificateProviderService,
        IAttestationCertificateValidator attestationCertificateValidator)
    {
        _jwsResponseParserService = androidSafetyNetJwsResponseParserService;
        _jwsResponseValidator = androidSafetyNetJwsResponseValidator;
        _attestationCertificateProviderService = attestationCertificateProviderService;
        _attestationCertificateValidator = attestationCertificateValidator;
    }

    /// <summary>
    /// Validates an Android SafetyNet attestation statement.
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
            throw new ArgumentException(
                "Android SafetyNet attestation statement cannot be read",
                nameof(attestationObjectData));
        }

        // Verify that response is a valid SafetyNet response of version ver by following the steps indicated by the
        // SafetyNet online documentation. As of this writing, there is only one format of the SafetyNet response and
        // ver is reserved for future use.
        if (!attestationStatementDict.TryGetValue(AttestationStatement.Version, out var version) ||
            version is not string versionString || string.IsNullOrWhiteSpace(versionString))
        {
            return ValidatorInternalResult.Invalid(
                "Android SafetyNet attestation statement version is missing or invalid");
        }

        if (!attestationStatementDict.TryGetValue(AttestationStatement.Response, out var response) ||
            response is not byte[] responseBytes || responseBytes.Length == 0)
        {
            return ValidatorInternalResult.Invalid(
                "Android SafetyNet attestation statement response is missing or invalid");
        }

        var jwsResponse = _jwsResponseParserService.Parse(responseBytes);
        if (jwsResponse == null)
        {
            return ValidatorInternalResult.Invalid(
                "Android SafetyNet attestation statement JWS response could not be parsed");
        }

        // Verify that the nonce attribute in the payload of response is identical to the Base64 encoding of the
        // SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
        if (jwsResponse.Nonce == null)
        {
            return ValidatorInternalResult.Invalid(
                "Android SafetyNet attestation statement JWS response is missing required nonce field");
        }

        var concatenatedData = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);
        var concatenatedDataHash = HashProvider.GetHash(concatenatedData, HashAlgorithmName.SHA256);

        var nonceHash = HashProvider.GetHash(Convert.FromBase64String(jwsResponse.Nonce), HashAlgorithmName.SHA256);

        if (!BytesArrayComparer.CompareNullable(nonceHash, concatenatedDataHash))
        {
            return ValidatorInternalResult.Invalid(
                "Android SafetyNet attestation statement response's nonce is not identical to the concatenation of authenticatorData and clientDataHash");
        }

        // Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the
        // SafetyNet online documentation.
        // https://web.archive.org/web/20180710064905/https://developer.android.com/training/safetynet/attestation#verify-compat-check
        var result = _jwsResponseValidator.PreValidate(jwsResponse);
        if (!result.IsValid)
        {
            return result;
        }

        var certificates = _attestationCertificateProviderService.GetCertificates(jwsResponse.Certificates!);

        // Use SSL hostname matching to verify that the leaf certificate was issued to the hostname attest.android.com
        var attestationCertificate = _attestationCertificateProviderService.GetAttestationCertificate(certificates);
        result = _attestationCertificateValidator.ValidateAndroidSafetyNet(attestationCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        // Use the certificate to verify the signature of the JWS message.
        // Check the data of the JWS message to make sure it matches the data within your original request.
        result = _jwsResponseValidator.Validate(jwsResponse, attestationCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        // If successful, return implementation-specific values representing attestation type Basic and attestation
        // trust path x5c.
        return new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.AndroidSafetyNet,
            AttestationType.Basic,
            [.. certificates]);
    }
}
