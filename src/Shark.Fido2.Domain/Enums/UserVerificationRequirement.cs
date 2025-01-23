using System.Runtime.Serialization;

namespace Shark.Fido2.Domain.Enums;

/// <summary>
/// 5.8.6. User Verification Requirement Enumeration (enum UserVerificationRequirement)
/// https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement
/// </summary>
public enum UserVerificationRequirement
{
    [EnumMember(Value = "required")]
    Required = 1,

    [EnumMember(Value = "preferred")]
    Preferred = 2,

    [EnumMember(Value = "discouraged")]
    Discouraged = 3,
}
