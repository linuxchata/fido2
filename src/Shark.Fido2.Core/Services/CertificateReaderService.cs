using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Services;

namespace Shark.Fido2.Core.Services;

internal sealed class CertificateReaderService : ICertificateReaderService
{
    public X509Certificate2 Read(string fileName, string certificatesDirectory = "Data/Certificates")
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(fileName, nameof(fileName));

        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        var certificatesPath = Path.Combine(baseDirectory, certificatesDirectory, fileName);
        var certificatesText = File.ReadAllLines(certificatesPath);

        if (certificatesText.Length == 0)
        {
            throw new FileNotFoundException($"No certificates found in {certificatesPath}");
        }

        if (certificatesText.Length > 1)
        {
            throw new InvalidOperationException($"Expected a single certificate in {certificatesPath}, but found {certificatesText.Length} certificates.");
        }

        var certificateByteArray = Convert.FromBase64String(certificatesText[0]);
        return new X509Certificate2(certificateByteArray);
    }
}
