using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public sealed class ServerPublicKeyCredentialGetOptionsResponse : ServerResponse
    {
        [JsonPropertyName("challenge")]
        public string Challenge { get; set; } = null!;

        [JsonPropertyName("timeout")]
        public ulong? Timeout { get; set; }

        [JsonPropertyName("rpId")]
        public string? RpId { get; set; }

        [JsonPropertyName("allowCredentials")]
        public DescriptorResponse[] AllowCredentials { get; set; } = null!;

        [JsonPropertyName("userVerification")]
        public string UserVerification { get; set; } = null!;
    }
}
