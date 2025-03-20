using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Metadata.Core.Abstractions;

namespace Shark.Fido2.Metadata.Core;

public sealed class CertificateValidator : ICertificateValidator
{
    public void ValidateX509Chain(
        X509Certificate2? rootCertificate,
        X509Certificate2 leafCertificate,
        List<string> certificates)
    {
        if (rootCertificate == null)
        {
            throw new InvalidOperationException("Root certificate is required");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online; // Configuration
        chain.ChainPolicy.VerificationTime = DateTime.Now;

        // Root certificate
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(rootCertificate);

        foreach (var certificate in certificates.Skip(1))
        {
            // Intermediate certificate
            var intermediateCertificate = new X509Certificate2(Convert.FromBase64String(certificate.ToString()!));
            chain.ChainPolicy.ExtraStore.Add(intermediateCertificate);
        }

        var isValid = chain.Build(leafCertificate);
        if (!isValid)
        {
            var errors = chain.ChainStatus.Select(x => x.StatusInformation).ToList();
            throw new InvalidOperationException(
                $"Invalid certificate. Errors:{Environment.NewLine}{string.Join(Environment.NewLine, errors)}");
        }
    }
}
