using System.Runtime.Serialization;

namespace Shark.Fido2.Domain.Enums;

/// <summary>
/// 5.4.5. Authenticator Attachment Enumeration (enum AuthenticatorAttachment)
/// https://www.w3.org/TR/webauthn-2/#enum-attachment
/// </summary>
public enum AuthenticatorAttachment
{
    [EnumMember(Value = "platform")]
    Platform = 1,

    [EnumMember(Value = "cross-platform")]
    CrossPlatform = 2,
}
