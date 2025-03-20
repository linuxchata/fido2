using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core;

public sealed class MetadataService : IMetadataService
{
    public async Task Refresh()
    {
        var metadataBlob = await GetMetadataBlob();

        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = 6 * 1024 * 1024, // Configuration
        };

        if (!handler.CanReadToken(metadataBlob))
        {
            throw new InvalidOperationException();
        }

        var jwtToken = handler.ReadJwtToken(metadataBlob);

        if (!jwtToken.Header.TryGetValue("x5c", out var x5c) || x5c is not List<object>)
        {
            throw new InvalidOperationException();
        }

        if (x5c is not List<object> x5cList)
        {
            throw new InvalidOperationException();
        }

        var rootCertificate = await GetRootCertificate();
        var certificates = x5cList.Select(a => a.ToString()!).ToList();
        var leafCertificate = new X509Certificate2(Convert.FromBase64String(certificates.FirstOrDefault()!));
        ValidateX509Chain(rootCertificate, leafCertificate, certificates);

        await ValidateBlob(handler, leafCertificate, metadataBlob);

        if (!jwtToken.Payload.TryGetValue("no", out var number))
        {
            throw new InvalidOperationException();
        }

        var result = new List<MetadataBlobPayloadEntry>(jwtToken.Claims.Count());

        jwtToken.Claims.ToList().ForEach(claim =>
        {
            if (claim.Type == "entries")
            {
                var payloadEntry = JsonSerializer.Deserialize<MetadataBlobPayloadEntry>(claim.Value);
                if (payloadEntry != null)
                {
                    result.Add(payloadEntry);
                }
            }
        });
    }

    private async Task<string> GetMetadataBlob()
    {
        using var client = new HttpClient();
        using var stream = await client.GetStreamAsync("https://mds3.fidoalliance.org/"); // Configuration
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private async Task<X509Certificate2?> GetRootCertificate()
    {
        using var client = new HttpClient();
        var byteArray = await client.GetByteArrayAsync("http://secure.globalsign.com/cacert/root-r3.crt"); // Configuration
        if (byteArray != null)
        {
            return new X509Certificate2(byteArray);
        }

        return null;
    }

    private X509Certificate2 ValidateX509Chain(
        X509Certificate2? rootCertificate,
        X509Certificate2 leafCertificate,
        List<string> certificates)
    {
        if (rootCertificate == null)
        {
            throw new InvalidOperationException();
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
            throw new InvalidOperationException();
        }

        return leafCertificate;
    }

    private async Task<bool> ValidateBlob(
        JwtSecurityTokenHandler handler,
        X509Certificate2 certificate,
        string metadataBlob)
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new X509SecurityKey(certificate),
        };

        try
        {
            var result = await handler.ValidateTokenAsync(metadataBlob, validationParameters);
            return result.IsValid;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
