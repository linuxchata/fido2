using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerPublicKeyCredentialDescriptor
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("transports")]
    public required string[] Transports { get; init; }
}
