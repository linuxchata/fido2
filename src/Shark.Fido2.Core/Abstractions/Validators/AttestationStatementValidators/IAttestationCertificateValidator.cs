using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// The interface representing the logic to validate X.509 certificates.
/// </summary>
public interface IAttestationCertificateValidator
{
    /// <summary>
    /// Validates a certificate for Packed attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate.</param>
    /// <param name="attestationObjectData">The attestation object data.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidatePacked(
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData);

    /// <summary>
    /// Validates a certificate for TPM attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate.</param>
    /// <param name="attestationObjectData">The attestation object data.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateTpm(
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData);

    /// <summary>
    /// Validates a certificate for Android Key attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate.</param>
    /// <param name="clientData">The client data containing challenge hash.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateAndroidKey(
        X509Certificate2 attestationCertificate,
        ClientData clientData);

    /// <summary>
    /// Validates a certificate for Android SafetyNet attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateAndroidSafetyNet(X509Certificate2 attestationCertificate);

    /// <summary>
    /// Validates a certificate for FIDO U2F attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateFidoU2F(X509Certificate2 attestationCertificate);

    /// <summary>
    /// Validates a certificate for Apple Anonymous attestation format.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 certificate.</param>
    /// <param name="nonce">The nonce to verify against the certificate extension.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateAppleAnonymous(X509Certificate2 attestationCertificate, byte[] nonce);
}
