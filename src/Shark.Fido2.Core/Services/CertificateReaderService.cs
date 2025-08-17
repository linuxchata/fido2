using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Services;

namespace Shark.Fido2.Core.Services;

internal sealed class CertificateReaderService : ICertificateReaderService
{
    public X509Certificate2 Read(string embeddedCertificateName)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(embeddedCertificateName, nameof(embeddedCertificateName));

        var certificates = ReadCertificateFromEmbeddedResource(embeddedCertificateName);

        return ParseCertiticate(embeddedCertificateName, certificates);
    }

    internal static List<string> ReadCertificateFromEmbeddedResource(string embeddedCertificateName)
    {
        var assembly = Assembly.GetExecutingAssembly();

        var fullEmbeddedCertificateName = $"{assembly.GetName().Name}.Data.Certificates.{embeddedCertificateName}";

        using var stream = assembly.GetManifestResourceStream(fullEmbeddedCertificateName)
            ?? throw new FileNotFoundException($"Embedded certificate '{fullEmbeddedCertificateName}' was not found.");

        using var reader = new StreamReader(stream);

        var certificates = new List<string>(1);
        string? certificate;
        while ((certificate = reader.ReadLine()) != null)
        {
            certificates.Add(certificate);
        }

        return certificates;
    }

    internal static X509Certificate2 ParseCertiticate(string embeddedCertificateName, List<string> certificates)
    {
        if (certificates.Count == 0)
        {
            throw new FileNotFoundException($"Certificates were not found in '{embeddedCertificateName}'.");
        }

        if (certificates.Count > 1)
        {
            throw new InvalidOperationException(
                $"Expected a single certificate in '{embeddedCertificateName}', but found {certificates.Count} certificates.");
        }

        var certificateByteArray = Convert.FromBase64String(certificates[0]);
        return new X509Certificate2(certificateByteArray);
    }
}
