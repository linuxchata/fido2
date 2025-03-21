using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Configurations;

namespace Shark.Fido2.Metadata.Core.Repositories;

public class HttpClientRepository : IHttpClientRepository
{
    private readonly Fido2MetadataServiceConfiguration _configuration;

    public HttpClientRepository(IOptions<Fido2MetadataServiceConfiguration> options)
    {
        _configuration = options.Value;
    }

    public async Task<string> GetMetadataBlob(CancellationToken cancellationToken)
    {
        using var client = new HttpClient();
        using var stream = await client.GetStreamAsync(_configuration.MetadataBlobLocationUrl, cancellationToken);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    public async Task<X509Certificate2?> GetRootCertificate(CancellationToken cancellationToken)
    {
        using var client = new HttpClient();
        var byteArray = await client.GetByteArrayAsync(_configuration.RootCertificateLocationUrl, cancellationToken);
        if (byteArray != null)
        {
            return new X509Certificate2(byteArray);
        }

        return null;
    }
}