using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Options;

/// <summary>
/// 5.4.4. Authenticator Selection Criteria
/// https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection.
/// </summary>
public class AuthenticatorSelectionCriteria
{
    public AuthenticatorAttachment? AuthenticatorAttachment { get; init; }

    public ResidentKeyRequirement ResidentKey { get; init; }

    public bool RequireResidentKey { get; init; } = false;

    public UserVerificationRequirement? UserVerification { get; init; }
}
