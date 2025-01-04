﻿using System;
using System.Reflection;
using System.Runtime.Serialization;

namespace Shark.Fido2.Models.Extensions
{
    public static class EnumExtensions
    {
        public static string GetValue<T>(this T enumValue) where T : Enum
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

        public static T ToEnum<T>(this string value) where T : struct, Enum
        {
            foreach (var field in typeof(T).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                var attribute = field.GetCustomAttribute<EnumMemberAttribute>();
                if (attribute?.Value == value)
                {
                    return (T)field.GetValue(null);
                }
            }

            throw new ArgumentException($"Value '{value}' can not be convert to {typeof(T).Name}");
        }
    }
}
