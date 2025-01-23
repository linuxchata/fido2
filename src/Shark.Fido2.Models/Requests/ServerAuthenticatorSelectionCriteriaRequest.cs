using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Requests;

public sealed class ServerAuthenticatorSelectionCriteriaRequest
{
    [JsonPropertyName("authenticatorAttachment")]
    public string AuthenticatorAttachment { get; set; } = null!;

    [JsonPropertyName("residentKey")]
    public string ResidentKey { get; set; } = null!;

    [JsonPropertyName("requireResidentKey")]
    public bool RequireResidentKey { get; set; } = false;

    [JsonPropertyName("userVerification")]
    public string? UserVerification { get; set; }
}