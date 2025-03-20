using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface ICertificateValidator
{
    void ValidateX509Chain(
        X509Certificate2? rootCertificate,
        X509Certificate2 leafCertificate,
        List<string> certificates);
}
