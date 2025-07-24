using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;

namespace Shark.Fido2.Metadata.Core.Repositories;

internal class HttpClientConformanceTestRepository : IHttpClientConformanceTestRepository
{
    public async Task<List<string>> GetMetadataBlobEndpoints(string remoteUrl, CancellationToken cancellationToken)
    {
        using var client = new HttpClient();

        var payload = new { endpoint = "https://localhost:8082/" };

        using var response = await client.PostAsJsonAsync(remoteUrl, payload, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        var apiResponse = JsonSerializer.Deserialize<ApiResponse>(content);
        if (apiResponse == null || apiResponse.status != "ok" || apiResponse.result is null)
        {
            return [];
        }

        return apiResponse.result.ToList();
    }

    public async Task<string> GetMetadataBlob(string endpoint, CancellationToken cancellationToken)
    {
        using var client = new HttpClient();
        using var stream = await client.GetStreamAsync(endpoint, cancellationToken);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    public async Task<X509Certificate2> GetRootCertificate(string url, CancellationToken cancellationToken)
    {
        using var client = new HttpClient();
        var response = await client.GetByteArrayAsync(url, cancellationToken);
        if (response == null || response.Length == 0)
        {
            throw new InvalidOperationException($"Root certificate cannot be obtained from {url}");
        }

        return new X509Certificate2(response);
    }

    private record ApiResponse(string status, string[] result);
}
