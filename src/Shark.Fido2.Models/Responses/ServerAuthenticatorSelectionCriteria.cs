using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public sealed class ServerAuthenticatorSelectionCriteria
    {
        [JsonPropertyName("authenticatorAttachment")]
        public string AuthenticatorAttachment { get; set; } = null!;

        [JsonPropertyName("residentKey")]
        public string ResidentKey { get; set; } = null!;

        [JsonPropertyName("requireResidentKey")]
        public bool RequireResidentKey { get; set; }

        [JsonPropertyName("userVerification")]
        public string UserVerification { get; set; } = null!;
    }
}
