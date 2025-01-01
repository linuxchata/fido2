using System.Text.Json.Serialization;
using Shark.Fido2.Domain.Constants;

namespace Shark.Fido2.Domain
{
    /// <summary>
    /// 5.4.4. Authenticator Selection Criteria
    /// https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection
    /// </summary>
    public class AuthenticatorSelectionCriteria
    {
        public string AuthenticatorAttachment { get; set; } = null!;

        public string ResidentKey { get; set; } = null!;

        public bool RequireResidentKey { get; set; } = false;

        public string UserVerification { get; set; } = ResidentKeyRequirement.Preferred;
    }
}
