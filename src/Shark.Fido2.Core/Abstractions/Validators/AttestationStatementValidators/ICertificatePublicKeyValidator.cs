using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// The interface representing the logic to validate the relationship between attestation certificates and
/// credential public keys.
/// </summary>
public interface ICertificatePublicKeyValidator
{
    /// <summary>
    /// Validates that the credential public key matches the public key in the attestation certificate.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 attestation certificate.</param>
    /// <param name="credentialPublicKey">The credential public key.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(X509Certificate2 attestationCertificate, CredentialPublicKey credentialPublicKey);
}
