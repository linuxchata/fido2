using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Core.Abstractions.Helpers;

public interface ICertificateAttestationStatementProvider
{
    bool IsCertificatePresent(Dictionary<string, object> attestationStatementDict);

    List<X509Certificate2> GetCertificates(Dictionary<string, object> attestationStatementDict);

    X509Certificate2 GetAttestationCertificate(List<X509Certificate2> certificates);
}
