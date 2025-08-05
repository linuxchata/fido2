using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate EC2 cryptographic signatures.
/// </summary>
public interface IEc2CryptographyValidator
{
    /// <summary>
    /// Validates a cryptographic signature using either a credential public key or an attestation certificate.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="credentialPublicKey">The credential's public key containing EC2 parameters.</param>
    /// <param name="attestationCertificate">The X.509 attestation certificate.</param>
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
    /// <param name="signature">The signature.</param>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <param name="attestationCertificate">The X.509 attestation certificate.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    bool IsValid(byte[] data, byte[] signature, int algorithm, X509Certificate2 attestationCertificate);
}
