using System.Net.Http.Json;
using Shark.Fido2.Sample.Blazor.Client.Abstractions.Services;
using Shark.Fido2.Sample.Blazor.Client.Models;
using Shark.Fido2.Sample.Blazor.Client.ViewModels;

namespace Shark.Fido2.Sample.Blazor.Client.Services;

public class CredentialService(HttpClient httpClient) : ICredentialService
{
    private const string BaseUrl = "api/credentialsdetails";

    public async Task<ResultModel<CredentialDetailsViewModel>> Get(string credentialId, CancellationToken cancellationToken)
    {
        try
        {
            var requestUrl = $"{BaseUrl}/{Uri.EscapeDataString(credentialId)}";
            var response = await httpClient.GetAsync(requestUrl, cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<CredentialDetailsViewModel>(cancellationToken);
                return ResultModel<CredentialDetailsViewModel>.Create(result);
            }
            else
            {
                var errorMessage = $"Failed to load public key credential details: {response.StatusCode}";
                return ResultModel<CredentialDetailsViewModel>.CreateFailed(errorMessage);
            }
        }
        catch
        {
            var errorMessage = $"Error loading credential details";
            return ResultModel<CredentialDetailsViewModel>.CreateFailed(errorMessage);
        }
    }
}
