using System.Net.Http.Json;
using Shark.Fido2.Sample.Blazor.Client.Abstractions.Services;
using Shark.Fido2.Sample.Blazor.Client.Models;
using Shark.Fido2.Sample.Blazor.Client.ViewModels;

namespace Shark.Fido2.Sample.Blazor.Client.Services;

public class CredentialClientService : ICredentialClientService
{
    private const string Path = "api/credential";

    private readonly HttpClient _httpClient;

    public CredentialClientService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<Response<CredentialDetailsViewModel>> Get(Uri baseUri, string id, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(baseUri, nameof(baseUri));
        ArgumentNullException.ThrowIfNullOrWhiteSpace(id, nameof(id));

        _httpClient.BaseAddress = baseUri;

        try
        {
            var requestUrl = $"{Path}/{Uri.EscapeDataString(id)}";
            var response = await _httpClient.GetAsync(requestUrl, cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<CredentialDetailsViewModel>(cancellationToken);
                return Response<CredentialDetailsViewModel>.Create(result);
            }
            else
            {
                var errorMessage = $"Failed to load public key credential details: {response.StatusCode}";
                return Response<CredentialDetailsViewModel>.CreateFailed(errorMessage);
            }
        }
        catch
        {
            var errorMessage = $"Error loading public key credential details";
            return Response<CredentialDetailsViewModel>.CreateFailed(errorMessage);
        }
    }
}
