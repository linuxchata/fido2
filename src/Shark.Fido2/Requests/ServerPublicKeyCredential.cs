using System.Text.Json.Serialization;

namespace Shark.Fido2.Requests;

public sealed class ServerPublicKeyCredential
{
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    [JsonPropertyName("rawId")]
    public required string RawId { get; set; }

    [JsonPropertyName("response")]
    public required ServerAuthenticatorAttestationResponse Response { get; set; }

    [JsonPropertyName("type")]
    public required string Type { get; set; }
}