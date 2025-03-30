using System.Runtime.Serialization;

namespace Shark.Fido2.Domain.Enums;

/// <summary>
/// 5.4.6. Resident Key Requirement Enumeration
/// https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement.
/// </summary>
public enum ResidentKeyRequirement
{
    /// <summary>
    /// This value indicates the Relying Party prefers creating a server-side credential, but will accept a client-side
    /// discoverable credential.
    /// </summary>
    [EnumMember(Value = "discouraged")]
    Discouraged = 1,

    /// <summary>
    /// This value indicates the Relying Party strongly prefers creating a client-side discoverable credential, but will
    /// accept a server-side credential. For example, user agents SHOULD guide the user through setting up user
    /// verification if needed to create a client-side discoverable credential in this case. This takes precedence over
    /// the setting of userVerification.
    /// </summary>
    [EnumMember(Value = "preferred")]
    Preferred = 2,

    /// <summary>
    /// This value indicates the Relying Party requires a client-side discoverable credential, and is prepared to receive
    /// an error if a client-side discoverable credential cannot be created.
    /// </summary>
    [EnumMember(Value = "required")]
    Required = 3,
}