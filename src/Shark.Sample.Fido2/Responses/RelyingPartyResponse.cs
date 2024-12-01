using System.Text.Json.Serialization;

namespace Shark.Sample.Fido2.Responses;

public sealed class RelyingPartyResponse
{
    [JsonPropertyName("id")]
    public required string Identifier { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }
}