using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public sealed class RelyingPartyResponse
    {
        [JsonPropertyName("id")]
        public string Identifier { get; set; } = null!;

        [JsonPropertyName("name")]
        public string Name { get; set; } = null!;
    }
}