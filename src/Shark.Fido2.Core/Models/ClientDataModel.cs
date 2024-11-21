using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Models
{
    public sealed class ClientDataModel
    {
        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("challenge")]
        public string? Challenge { get; set; }

        [JsonPropertyName("origin")]
        public string? Origin { get; set; }

        [JsonPropertyName("crossOrigin")]
        public bool CrossOrigin { get; set; }
    }
}
