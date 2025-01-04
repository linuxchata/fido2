using System.Text.Json.Serialization;
using Shark.Fido2.Domain.Constants;

namespace Shark.Fido2.Models.Requests
{
    public class ServerPublicKeyCredentialCreationOptionsRequest
    {
        [JsonPropertyName("username")]
        [JsonRequired]
        public string Username { get; set; } = null!;

        [JsonPropertyName("displayName")]
        [JsonRequired]
        public string DisplayName { get; set; } = null!;

        [JsonPropertyName("authenticatorSelection")]
        public ServerAuthenticatorSelectionCriteriaRequest? AuthenticatorSelection { get; set; }

        [JsonPropertyName("attestation")]
        public string? Attestation { get; set; }
    }
}