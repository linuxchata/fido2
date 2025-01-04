using System.Runtime.Serialization;

namespace Shark.Fido2.Domain.Enums
{
    /// <summary>
    /// 5.4.6. Resident Key Requirement Enumeration
    /// https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement
    /// </summary>
    public enum ResidentKeyRequirement
    {
        [EnumMember(Value = "discouraged")]
        Discouraged = 1,

        [EnumMember(Value = "preferred")]
        Preferred = 2,

        [EnumMember(Value = "required")]
        Required = 3,
    }
}