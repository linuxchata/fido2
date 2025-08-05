using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate OKP cryptographic signatures.
/// </summary>
public interface IOkpCryptographyValidator
{
    /// <summary>
    /// Validates a cryptographic signature using a credential public key.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="credentialPublicKey">The credential's public key containing OKP parameters.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    bool IsValid(byte[] data, byte[] signature, CredentialPublicKey credentialPublicKey);
}
