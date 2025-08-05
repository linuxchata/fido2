using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// The interface representing the logic to validate signatures in attestation statements.
/// </summary>
public interface ISignatureAttestationStatementValidator
{
    /// <summary>
    /// Validates a signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="credentialPublicKey">The credential's public key.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(byte[] data, byte[] signature, CredentialPublicKey credentialPublicKey);

    /// <summary>
    /// Validates a generic attestation statement signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="attestationStatementDict">The attestation statement dictionary.</param>
    /// <param name="credentialPublicKey">The credential's public key.</param>
    /// <param name="attestationCertificate">The X.509 attestation certificate.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(
        byte[] data,
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2? attestationCertificate = null);

    /// <summary>
    /// Validates a TPM attestation statement signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="attestationStatementDict">The attestation statement dictionary.</param>
    /// <param name="keyType">The key type.</param>
    /// <param name="algorithm">The signing algorithm.</param>
    /// <param name="attestationCertificate">The X.509 attestation certificate.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
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
    /// <param name="attestationStatementDict">The attestation statement dictionary.</param>
    /// <param name="credentialPublicKey">The credential's public key.</param>
    /// <param name="attestationCertificate">The X.509 attestation certificate.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateFido2U2f(
        byte[] data,
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2 attestationCertificate);
}
