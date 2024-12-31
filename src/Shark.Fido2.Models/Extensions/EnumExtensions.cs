using System;
using System.Reflection;
using System.Runtime.Serialization;

namespace Shark.Fido2.Models.Extensions
{
    public static class EnumExtensions
    {
        public static string GetEnumMemberValue<T>(this T enumValue) where T : Enum
        {
            var memberInfo = typeof(T).GetMember(enumValue.ToString());
            if (memberInfo?.Length > 0)
            {
                var attribute = memberInfo[0].GetCustomAttribute<EnumMemberAttribute>();
                if (attribute != null)
                {
                    return attribute.Value;
                }
            }

            return enumValue.ToString();
        }
    }
}
