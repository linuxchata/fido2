using System.Runtime.Serialization;

namespace Shark.Fido2.Common.Tests.Extensions;

public enum TestEnum
{
    [EnumMember(Value = "custom-value")]
    WithAttribute,
    WithoutAttribute,
}
