using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Configurations;

namespace Shark.Fido2.Metadata.Core.Repositories;

[ExcludeFromCodeCoverage]
internal sealed class HttpClientRepository : IHttpClientRepository
{
    private readonly MetadataServiceConfiguration _configuration;

    public HttpClientRepository(IOptions<MetadataServiceConfiguration> options)
    {
        _configuration = options.Value;
    }

    public async Task<string> GetMetadataBlob(CancellationToken cancellationToken)
    {
        using var client = new HttpClient();
        using var stream = await client.GetStreamAsync(_configuration.MetadataBlobLocation, cancellationToken);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(cancellationToken);
    }

    public async Task<X509Certificate2> GetRootCertificate(CancellationToken cancellationToken)
    {
        var url = _configuration.RootCertificateLocationUrl;

        using var client = new HttpClient();
        var response = await client.GetByteArrayAsync(url, cancellationToken);
        if (response == null || response.Length == 0)
        {
            throw new InvalidOperationException($"Root certificate cannot be obtained from {url}");
        }

        return new X509Certificate2(response);
    }

    public async Task<List<X509Certificate2>> GetCertificates(string url, CancellationToken cancellationToken)
    {
        using var client = new HttpClient();
        var response = await client.GetStringAsync(url, cancellationToken);
        if (string.IsNullOrWhiteSpace(response))
        {
            throw new InvalidOperationException($"Certificates cannot be obtained from {url}");
        }

        var result = new List<X509Certificate2>();
        var certificates = SplitCertificates(response);
        foreach (var certificate in certificates)
        {
            var bytes = Convert.FromBase64String(certificate);
            result.Add(new X509Certificate2(bytes));
        }

        return result;
    }

    private static string[] SplitCertificates(string pem)
    {
        return pem.Split(["-----END CERTIFICATE-----"], StringSplitOptions.RemoveEmptyEntries)
            .Select(cert => cert.Replace("-----BEGIN CERTIFICATE-----", string.Empty).Trim())
            .ToArray();
    }
}