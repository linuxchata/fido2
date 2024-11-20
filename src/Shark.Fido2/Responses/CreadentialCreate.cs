using System.Text.Json.Serialization;

namespace Shark.Fido2.Responses;

public sealed class CredentialGetOptionsResponse
{
    [JsonPropertyName("rp")]
    public required RelyingPartyResponse RelyingParty { get; set; }

    [JsonPropertyName("user")]
    public required UserResponse User { get; set; }

    [JsonPropertyName("challenge")]
    public required string Challenge { get; set; }
}