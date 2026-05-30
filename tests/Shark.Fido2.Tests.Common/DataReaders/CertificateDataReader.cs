using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Tests.Common.DataReaders;

public static class CertificateDataReader
{
    public static X509Certificate2[] Read(string fileName)
    {
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        var certificatesPath = Path.Combine(baseDirectory, "Data/Certificates", fileName);
        var certificatesText = File.ReadAllLines(certificatesPath);

        var certificates = new List<X509Certificate2>();

        foreach (var certificate in certificatesText)
        {
            var certificateByteArray = Convert.FromBase64String(certificate);
#if NET9_0_OR_GREATER
            var x509Certificate = X509CertificateLoader.LoadCertificate(certificateByteArray);
#else
            var x509Certificate = new X509Certificate2(certificateByteArray);
#endif
            certificates.Add(x509Certificate);
        }

        return certificates.ToArray();
    }
}
