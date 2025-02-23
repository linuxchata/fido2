using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Core.Abstractions.Services;

public interface IAttestationCertificateProviderService
{
    bool AreCertificatesPresent(Dictionary<string, object> attestationStatementDict);

    List<X509Certificate2> GetCertificates(Dictionary<string, object> attestationStatementDict);

    List<X509Certificate2> GetCertificates(List<object> certificates);

    X509Certificate2 GetAttestationCertificate(List<X509Certificate2> certificates);
}
