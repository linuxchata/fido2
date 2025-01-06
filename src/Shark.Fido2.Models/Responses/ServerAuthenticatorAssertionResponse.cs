using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    /// <summary>
    /// 7.4.3.3. ServerAuthenticatorAssertionResponse
    /// </summary>
    public sealed class ServerAuthenticatorAssertionResponse : ServerAuthenticatorResponse
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
