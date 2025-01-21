using System.Runtime.Serialization;

namespace Shark.Fido2.Domain.Enums
{
    public enum TokenBindingStatus
    {
        [EnumMember(Value = "present")]
        Present = 0,

        [EnumMember(Value = "supported")]
        Supported = 1,

        [EnumMember(Value = "not-supported")]
        NotSupported = 2,
    }
}
