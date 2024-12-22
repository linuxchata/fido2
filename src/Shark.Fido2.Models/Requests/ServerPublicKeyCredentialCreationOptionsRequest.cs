using System.Text.Json.Serialization;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Requests
{
    public class ServerPublicKeyCredentialCreationOptionsRequest
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = null!;

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; } = null!;

        [JsonPropertyName("authenticatorSelection")]
        public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; set; }

        [JsonPropertyName("attestation")]
        public string Attestation { get; set; } = AttestationConveyancePreference.None;
    }
}