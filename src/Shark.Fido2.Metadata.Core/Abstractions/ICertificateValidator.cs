using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface ICertificateValidator
{
    void ValidateX509Chain(X509Certificate2? rootCertificate, List<X509Certificate2> certificates);
}
