using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// Validates cryptographic signatures using public key credentials.
/// Supports OKP (Octet Key Pair) cryptographic algorithms.
/// </summary>
public interface IOkpCryptographyValidator
{
    /// <summary>
    /// Validates a cryptographic signature using either a credential public key.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="credentialPublicKey">The credential's public key containing OKP parameters.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    bool IsValid(byte[] data, byte[] signature, CredentialPublicKey credentialPublicKey);
}
