namespace Shark.Fido2.Common.Extensions;

public static class ConvertExtensions
{
    public static string ToBase64Url(this byte[] bytes)
    {
        var base64String = Convert.ToBase64String(bytes);
        return base64String.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    public static byte[] FromBase64Url(this string @string)
    {
        var base64String = @string.Replace('-', '+').Replace('_', '/');

        var padding = base64String.Length % 4;
        if (padding > 0)
        {
            base64String = base64String.PadRight(base64String.Length + 4 - padding, '=');
        }

        return Convert.FromBase64String(base64String);
    }
}
