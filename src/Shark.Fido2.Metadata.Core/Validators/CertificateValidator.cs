﻿using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Metadata.Core.Abstractions;

namespace Shark.Fido2.Metadata.Core.Validators;

internal sealed class CertificateValidator : ICertificateValidator
{
    private readonly TimeProvider _timeProvider;

    public CertificateValidator(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;
    }

    public void ValidateX509Chain(X509Certificate2? rootCertificate, List<X509Certificate2> certificates)
    {
        if (rootCertificate == null)
        {
            throw new InvalidOperationException("Root certificate is required");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online; // Configuration
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = _timeProvider.GetLocalNow().DateTime;

        // Root certificate
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(rootCertificate);

        foreach (var intermediateCertificate in certificates.Skip(1))
        {
            // Intermediate certificate
            chain.ChainPolicy.ExtraStore.Add(intermediateCertificate);
        }

        var leafCertificate = certificates[0];
        var isValid = chain.Build(leafCertificate);
        if (!isValid)
        {
            var errors = chain.ChainStatus.Select(x => x.StatusInformation);
            throw new InvalidOperationException(
                $"Invalid certificate. Errors:{Environment.NewLine}{string.Join(Environment.NewLine, errors)}");
        }
    }
}
