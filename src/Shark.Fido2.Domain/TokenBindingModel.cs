using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Models
{
    public class TokenBindingModel
    {
        [JsonPropertyName("status")]
        public TokenBindingStatus Status { get; set; }

        [JsonPropertyName("id")]
        public string? Id { get; set; }
    }
}
