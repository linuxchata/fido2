using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;

namespace Shark.Fido2.Metadata.Core;

public class HttpClientRepository : IHttpClientRepository
{
    public async Task<string> GetMetadataBlob()
    {
        using var client = new HttpClient();
        using var stream = await client.GetStreamAsync("https://mds3.fidoalliance.org/"); // Configuration
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    public async Task<X509Certificate2?> GetRootCertificate()
    {
        using var client = new HttpClient();
        var byteArray = await client.GetByteArrayAsync("http://secure.globalsign.com/cacert/root-r3.crt"); // Configuration
        if (byteArray != null)
        {
            return new X509Certificate2(byteArray);
        }

        return null;
    }
}