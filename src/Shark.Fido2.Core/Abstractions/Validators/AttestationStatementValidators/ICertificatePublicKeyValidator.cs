using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// Validates the relationship between an attestation certificate and credential public key.
/// </summary>
public interface ICertificatePublicKeyValidator
{
    /// <summary>
    /// Validates that the credential public key matches the public key in the attestation certificate.
    /// </summary>
    /// <param name="attestationCertificate">The X.509 attestation certificate to validate.</param>
    /// <param name="credentialPublicKey">The credential public key to compare against.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    ValidatorInternalResult Validate(X509Certificate2 attestationCertificate, CredentialPublicKey credentialPublicKey);
}
