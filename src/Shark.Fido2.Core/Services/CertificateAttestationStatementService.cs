using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Services;

namespace Shark.Fido2.Core.Services;

internal class CertificateAttestationStatementService : ICertificateAttestationStatementService
{
    private const string Certificate = "x5c";

    public bool AreCertificatesPresent(Dictionary<string, object> attestationStatementDict)
    {
        return attestationStatementDict.TryGetValue(Certificate, out _);
    }

    public List<X509Certificate2> GetCertificates(Dictionary<string, object> attestationStatementDict)
    {
        if (!attestationStatementDict.TryGetValue(Certificate, out var x5c) || x5c is not List<object>)
        {
            return [];
        }

        var certificates = (List<object>)x5c;
        var attestationTrustPath = new List<X509Certificate2>();

        foreach (var certificate in certificates)
        {
            var x509Certificate = new X509Certificate2((byte[])certificate);
            attestationTrustPath.Add(x509Certificate);
        }

        return attestationTrustPath;
    }

    public X509Certificate2 GetAttestationCertificate(List<X509Certificate2> certificates)
    {
        var attestationCertificate = certificates.FirstOrDefault();
        return attestationCertificate ??
            throw new ArgumentException("Attestation statement certificate is not found");
    }
}
