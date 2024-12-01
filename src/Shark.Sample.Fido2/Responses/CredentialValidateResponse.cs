using System.Text.Json.Serialization;

namespace Shark.Sample.Fido2.Responses;

public sealed class CredentialValidateResponse
{
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; set; }
}