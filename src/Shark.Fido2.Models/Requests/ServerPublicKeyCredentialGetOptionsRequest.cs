using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Requests
{
    public class ServerPublicKeyCredentialGetOptionsRequest
    {
        [JsonPropertyName("username")]
        [JsonRequired]
        public string Username { get; set; } = null!;

        [JsonPropertyName("userVerification")]
        public string? UserVerification { get; set; }
    }
}
