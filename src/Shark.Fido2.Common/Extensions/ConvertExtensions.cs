namespace Shark.Fido2.Common.Extensions;

public static class ConvertExtensions
{
    public static string ToBase64Url(this byte[] bytes)
    {
        var base64String = Convert.ToBase64String(bytes);
        return base64String.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
