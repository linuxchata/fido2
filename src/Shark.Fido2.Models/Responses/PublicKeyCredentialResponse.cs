using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public sealed class PublicKeyCredentialResponse
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = null!;

        [JsonPropertyName("rawId")]
        public string RawId { get; set; } = null!;

        [JsonPropertyName("response")]
        public AuthenticatorAttestationResponse Response { get; set; } = null!;

        [JsonPropertyName("type")]
        public string Type { get; set; } = null!;
    }
}