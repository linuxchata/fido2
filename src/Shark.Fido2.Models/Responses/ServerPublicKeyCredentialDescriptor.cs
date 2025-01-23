using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerPublicKeyCredentialDescriptor
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = null!;

    [JsonPropertyName("id")]
    public string Id { get; set; } = null!;

    [JsonPropertyName("transports")]
    public string[] Transports { get; set; } = null!;
}
