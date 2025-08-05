using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to retrive attestation certificates.
/// </summary>
public interface IAttestationCertificateProviderService
{
    /// <summary>
    /// Checks if certificates are present in the attestation statement dictionary.
    /// </summary>
    /// <param name="attestationStatementDict">The attestation statement dictionary.</param>
    /// <returns>True if certificates are present; otherwise, false.</returns>
    bool AreCertificatesPresent(Dictionary<string, object> attestationStatementDict);

    /// <summary>
    /// Gets certificates from an attestation statement dictionary.
    /// </summary>
    /// <param name="attestationStatementDict">The attestation statement dictionary.</param>
    /// <returns>A list of X.509 certificates.</returns>
    List<X509Certificate2> GetCertificates(Dictionary<string, object> attestationStatementDict);

    /// <summary>
    /// Gets a list of certificates.
    /// </summary>
    /// <param name="certificates">The list of certificate objects.</param>
    /// <returns>A list of X.509 certificates.</returns>
    List<X509Certificate2> GetCertificates(List<object> certificates);

    /// <summary>
    /// Gets the attestation certificate from a list of certificates.
    /// </summary>
    /// <param name="certificates">The list of certificates.</param>
    /// <returns>The X.509 attestation certificate.</returns>
    X509Certificate2 GetAttestationCertificate(List<X509Certificate2> certificates);
}
