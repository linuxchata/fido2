using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// Validates X.509 certificates used in FIDO2 attestation statements.
/// This validator ensures that attestation certificates meet the requirements specified in the FIDO2 standard
/// for different attestation formats.
/// </summary>
public interface IAttestationCertificateValidator
{
    /// <summary>
    /// Validates a certificate for Packed attestation format according to § 8.2.1 requirements.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate to validate.</param>
    /// <param name="attestationObjectData">The attestation object data containing AAGUID and other metadata.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidatePacked(
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData);

    /// <summary>
    /// Validates a certificate for TPM attestation format according to § 8.3.1 requirements.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate to validate.</param>
    /// <param name="attestationObjectData">The attestation object data containing AAGUID and other metadata.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    /// <remarks>
    ValidatorInternalResult ValidateTpm(
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData);

    /// <summary>
    /// Validates a certificate for Android Key attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate to validate.</param>
    /// <param name="clientData">The client data containing challenge hash.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    /// <remarks>
    ValidatorInternalResult ValidateAndroidKey(
        X509Certificate2 attestationCertificate,
        ClientData clientData);

    /// <summary>
    /// Validates a certificate for Android SafetyNet attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate to validate.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateAndroidSafetyNet(X509Certificate2 attestationCertificate);

    /// <summary>
    /// Validates a certificate chain using the system's certificate authority store.
    /// </summary>
    /// <param name="certificates">The list of certificates forming the chain.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateChainOfTrustWithSystemCa(List<X509Certificate2> certificates);

    /// <summary>
    /// Validates a certificate for FIDO U2F attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate to validate.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateFidoU2f(X509Certificate2 attestationCertificate);

    /// <summary>
    /// Validates a certificate for Apple Anonymous attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate to validate.</param>
    /// <param name="nonce">The nonce to verify against the certificate extension.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateAppleAnonymous(X509Certificate2 attestationCertificate, byte[] nonce);
}
