using System.Text.Json.Serialization;

namespace Shark.Fido2.Domain
{
    public class TokenBinding
    {
        [JsonPropertyName("status")]
        public TokenBindingStatus Status { get; set; }

        [JsonPropertyName("id")]
        public string? Id { get; set; }
    }
}
