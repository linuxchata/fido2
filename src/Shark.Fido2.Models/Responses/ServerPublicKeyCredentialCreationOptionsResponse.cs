using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public sealed class ServerPublicKeyCredentialCreationOptionsResponse : ServerResponse
    {
        [JsonPropertyName("rp")]
        public RelyingPartyResponse RelyingParty { get; set; } = null!;

        [JsonPropertyName("user")]
        public UserResponse User { get; set; } = null!;

        [JsonPropertyName("challenge")]
        public string Challenge { get; set; } = null!;

        [JsonPropertyName("timeout")]
        public uint Timeout { get; set; }
    }
}