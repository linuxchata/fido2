using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public sealed class AuthenticatorAttestationResponse
    {
        [JsonPropertyName("clientDataJSON")]
        public string ClientDataJson { get; set; } = null!;

        [JsonPropertyName("attestationObject")]
        public string AttestationObject { get; set; } = null!;

        [JsonPropertyName("signature")]
        public string? Signature { get; set; }

        [JsonPropertyName("userHandler")]
        public string? UserHandler { get; set; }
    }
}