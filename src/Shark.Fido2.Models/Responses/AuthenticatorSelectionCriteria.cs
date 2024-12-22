using System.Text.Json.Serialization;
using Shark.Fido2.Domain.Constants;

namespace Shark.Fido2.Models.Responses
{
    /// <summary>
    /// 5.4.4. Authenticator Selection Criteria
    /// https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection
    /// </summary>
    public class AuthenticatorSelectionCriteria
    {
        [JsonPropertyName("authenticatorAttachment")]
        public string? AuthenticatorAttachment { get; set; }

        [JsonPropertyName("residentKey")]
        public string? ResidentKey { get; set; }

        [JsonPropertyName("requireResidentKey")]
        public bool RequireResidentKey { get; set; } = false;

        [JsonPropertyName("userVerification")]
        public string? UserVerification { get; set; } = ResidentKeyRequirement.Preferred;
    }
}