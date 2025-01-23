using System.Runtime.Serialization;

namespace Shark.Fido2.Domain.Enums;

/// <summary>
/// 5.8.4. Authenticator Transport Enumeration (enum AuthenticatorTransport)
/// https://www.w3.org/TR/webauthn-2/#enum-transport
/// </summary>
public enum AuthenticatorTransport
{
    [EnumMember(Value = "usb")]
    Usb = 0,

    [EnumMember(Value = "nfc")]
    Nfc,

    [EnumMember(Value = "ble")]
    Ble,

    [EnumMember(Value = "internal")]
    Internal,
}
