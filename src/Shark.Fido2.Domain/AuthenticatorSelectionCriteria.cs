using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain;

/// <summary>
/// 5.4.4. Authenticator Selection Criteria
/// https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection
/// </summary>
public class AuthenticatorSelectionCriteria
{
    public AuthenticatorAttachment AuthenticatorAttachment { get; set; }

    public ResidentKeyRequirement ResidentKey { get; set; }

    public bool RequireResidentKey { get; set; } = false;

    public UserVerificationRequirement? UserVerification { get; set; }
}
