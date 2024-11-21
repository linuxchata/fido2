using System.Text.Json.Serialization;

namespace Shark.Sample.Fido2.Requests;

public sealed class PublicKeyCredentialResponse
{
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    [JsonPropertyName("rawId")]
    public required string RawId { get; set; }

    [JsonPropertyName("response")]
    public required AuthenticatorAttestationResponse Response { get; set; }

    [JsonPropertyName("type")]
    public required string Type { get; set; }
}