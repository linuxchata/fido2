using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// Validates signatures in attestation statements for different attestation formats.
/// </summary>
public interface ISignatureAttestationStatementValidator
{
    /// <summary>
    /// Validates a signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="credentialPublicKey">The credential's public key.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    ValidatorInternalResult Validate(byte[] data, byte[] signature, CredentialPublicKey credentialPublicKey);

    /// <summary>
    /// Validates a generic attestation statement signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="attestationStatementDict">The attestation statement dictionary containing The signature to verify.</param>
    /// <param name="credentialPublicKey">The credential's public key.</param>
    /// <param name="attestationCertificate">Optional attestation certificate.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    ValidatorInternalResult Validate(
        byte[] data,
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2? attestationCertificate = null);

    /// <summary>
    /// Validates a TPM attestation statement signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="attestationStatementDict">The attestation statement dictionary containing the TPM-specific data.</param>
    /// <param name="keyType">The type of key used in the TPM.</param>
    /// <param name="algorithm">The algorithm used for signing.</param>
    /// <param name="attestationCertificate">The TPM attestation certificate.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    ValidatorInternalResult ValidateTpm(
        byte[] data,
        Dictionary<string, object> attestationStatementDict,
        KeyType keyType,
        int algorithm,
        X509Certificate2 attestationCertificate);

    /// <summary>
    /// Validates a FIDO U2F attestation statement signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="attestationStatementDict">The attestation statement dictionary containing the U2F-specific data.</param>
    /// <param name="credentialPublicKey">The credential's public key.</param>
    /// <param name="attestationCertificate">The U2F attestation certificate.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    ValidatorInternalResult ValidateFido2U2f(
        byte[] data,
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2 attestationCertificate);
}
