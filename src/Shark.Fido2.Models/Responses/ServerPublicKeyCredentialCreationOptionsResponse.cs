using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public sealed class ServerPublicKeyCredentialCreationOptionsResponse : ServerResponse
    {
        [JsonPropertyName("rp")]
        public ServerPublicKeyCredentialRpEntity RelyingParty { get; set; } = null!;

        [JsonPropertyName("user")]
        public ServerPublicKeyCredentialUserEntity User { get; set; } = null!;

        [JsonPropertyName("pubKeyCredParams")]
        public ServerPublicKeyCredentialParameters[] Parameters { get; set; } = null!;

        [JsonPropertyName("challenge")]
        public string Challenge { get; set; } = null!;

        [JsonPropertyName("timeout")]
        public ulong Timeout { get; set; }

        [JsonPropertyName("excludeCredentials")]
        public ServerPublicKeyCredentialDescriptor[] ExcludeCredentials { get; set; } = null!;

        [JsonPropertyName("authenticatorSelection")]
        public ServerAuthenticatorSelectionCriteria AuthenticatorSelection { get; set; } = null!;

        [JsonPropertyName("attestation")]
        public string Attestation { get; set; } = null!;
    }
}