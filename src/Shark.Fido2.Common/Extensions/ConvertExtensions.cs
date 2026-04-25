using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Shark.Fido2.Common.Extensions;

public static class ConvertExtensions
{
    public static string ToBase64Url(this byte[] bytes)
    {
        return Base64UrlEncoder.Encode(bytes);
    }

    public static byte[] FromBase64Url(this string base64Url)
    {
        try
        {
            return Base64UrlEncoder.DecodeBytes(base64Url);
        }
        catch (FormatException)
        {
            return Encoding.UTF8.GetBytes(base64Url);
        }
    }

    public static bool IsBase64Url(this string base64Url)
    {
        if (string.IsNullOrEmpty(base64Url))
        {
            return false;
        }

        var span = base64Url.AsSpan().TrimEnd('=');
        var remainder = span.Length % 4;

        if (remainder == 1)
        {
            return false;
        }

        foreach (var c in span)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')
            {
                return false;
            }
        }

        return remainder switch
        {
            2 => (GetBase64UrlValue(span[^1]) & 0xF) == 0,
            3 => (GetBase64UrlValue(span[^1]) & 0x3) == 0,
            _ => true
        };
    }

    private static int GetBase64UrlValue(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '-' => 62,
        '_' => 63,
        _ => -1
    };
}
