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
        return Base64UrlEncoder.DecodeBytes(base64Url);
    }

    public static bool IsBase64Url(this string base64Url)
    {
        try
        {
            Base64UrlEncoder.Decode(base64Url);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
