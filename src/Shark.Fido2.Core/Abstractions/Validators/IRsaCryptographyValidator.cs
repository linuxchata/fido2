using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// Validates cryptographic signatures using public key credentials or X.509 certificates.
/// Supports RSA cryptographic algorithms.
/// </summary>
public interface IRsaCryptographyValidator
{
    /// <summary>
    /// Validates a cryptographic signature using either a credential public key or an attestation certificate.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="credentialPublicKey">The credential's public key containing RSA parameters.</param>
    /// <param name="attestationCertificate">Optional X.509 certificate. If provided, its public key will be used instead of the credential public key.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    bool IsValid(
        byte[] data,
        byte[] signature,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2? attestationCertificate = null);

    /// <summary>
    /// Validates a cryptographic signature using an X.509 certificate and specified algorithm.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="algorithm">The algorithm identifier (maps to RSA algorithm parameters).</param>
    /// <param name="attestationCertificate">The X.509 certificate containing the public key for verification.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    bool IsValid(byte[] data, byte[] signature, int algorithm, X509Certificate2 attestationCertificate);
}
