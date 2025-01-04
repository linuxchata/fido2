using System.Runtime.Serialization;

namespace Shark.Fido2.Domain.Enums
{
    public enum UserVerificationRequirement
    {
        [EnumMember(Value = "required")]
        Required = 1,

        [EnumMember(Value = "preferred")]
        Preferred = 2,

        [EnumMember(Value = "discouraged")]
        Discouraged = 3,
    }
}
