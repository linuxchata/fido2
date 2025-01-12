using System.Text.Json.Serialization;

namespace Shark.Fido2.Domain
{
    /// <summary>
    /// 5.8.1. Client Data Used in WebAuthn Signatures
    /// https://www.w3.org/TR/webauthn-2/#dictionary-client-data
    /// </summary>
    public sealed class ClientData
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
        public TokenBinding? TokenBinding { get; set; }

        [JsonIgnore]
        public byte[] ClientDataHash { get; set; } = null!;
    }
}
