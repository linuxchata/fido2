namespace Shark.Fido2.Core.Converters;

/// <summary>
/// Converter for Base64URL
/// </summary>
public static class Base64UrlConverter
{
    public static string ToBase64(string base64Url)
    {
        if (base64Url == null)
        {
            throw new ArgumentNullException(nameof(base64Url));
        }

        // Replace Base64URL characters with Base64 equivalents
        var result = base64Url.Replace('-', '+').Replace('_', '/');

        // Add padding if necessary
        var padding = result.Length % 4;
        if (padding > 0)
        {
            result += new string('=', 4 - padding);
        }

        return result;
    }
}
