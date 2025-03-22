using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Metadata.Core.Abstractions;

namespace Shark.Fido2.Metadata.Core;

internal sealed class CertificateValidator : ICertificateValidator
{
    public void ValidateX509Chain(
        X509Certificate2? rootCertificate,
        X509Certificate2 leafCertificate,
        List<X509Certificate2> certificates)
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

        foreach (var intermediateCertificate in certificates.Skip(1))
        {
            // Intermediate certificate
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
