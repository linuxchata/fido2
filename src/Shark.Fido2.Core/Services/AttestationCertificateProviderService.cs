using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Constants;

namespace Shark.Fido2.Core.Services;

internal sealed class AttestationCertificateProviderService : IAttestationCertificateProviderService
{
    public bool AreCertificatesPresent(Dictionary<string, object> attestationStatementDict)
    {
        return attestationStatementDict.TryGetValue(AttestationStatement.Certificate, out _);
    }

    public List<X509Certificate2> GetCertificates(Dictionary<string, object> attestationStatementDict)
    {
        if (!attestationStatementDict.TryGetValue(AttestationStatement.Certificate, out var x5c) ||
            x5c is not List<object>)
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

    public List<X509Certificate2> GetCertificates(List<object> certificates)
    {
        var attestationTrustPath = new List<X509Certificate2>();

        foreach (var certificate in certificates)
        {
            var certificateByteArray = Convert.FromBase64String((string)certificate);
            var x509Certificate = new X509Certificate2(certificateByteArray);
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
