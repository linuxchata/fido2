using System.Text.Json.Serialization;

namespace Shark.Fido2.Responses;

public sealed class RelyingPartyResponse
{
    [JsonPropertyName("id")]
    public required string Identifier { get; set; }

    [JsonPropertyName("name")]
    public required string Name { get; set; }
}