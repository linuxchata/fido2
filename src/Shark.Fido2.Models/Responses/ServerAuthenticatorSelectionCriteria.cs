using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerAuthenticatorSelectionCriteria
{
    [JsonPropertyName("authenticatorAttachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthenticatorAttachment { get; set; }

    [JsonPropertyName("residentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResidentKey { get; set; }

    [JsonPropertyName("requireResidentKey")]
    public bool RequireResidentKey { get; set; }

    [JsonPropertyName("userVerification")]
    public string UserVerification { get; set; } = null!;
}
