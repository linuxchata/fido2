using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to validate X.509 certificate chains.
/// </summary>
public interface ICertificateValidator
{
    /// <summary>
    /// Validates an X.509 certificate chain.
    /// </summary>
    /// <param name="rootCertificate">The root certificate.</param>
    /// <param name="certificates">The list of certificates.</param>
    void ValidateX509Chain(X509Certificate2? rootCertificate, List<X509Certificate2> certificates);
}
