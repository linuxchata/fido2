using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Models
{
    /// <summary>
    /// 5.8.1. Client Data Used in WebAuthn Signatures
    /// </summary>
    public sealed class ClientDataModel
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = null!;

        [JsonPropertyName("challenge")]
        public string Challenge { get; set; } = null!;

        [JsonPropertyName("origin")]
        public string Origin { get; set; } = null!;

        [JsonPropertyName("crossOrigin")]
        public bool CrossOrigin { get; set; }

        [JsonPropertyName("tokenBinding")]
        public TokenBindingModel? TokenBinding { get; set; }
    }
}
