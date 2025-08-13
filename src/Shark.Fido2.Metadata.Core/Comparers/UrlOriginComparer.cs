namespace Shark.Fido2.Metadata.Core.Comparers;

internal static class UrlOriginComparer
{
    internal static bool CompareOrigins(string left, string right)
    {
        try
        {
            Uri uriLeft = new(left);
            Uri uriRight = new(right);

            return uriLeft.Scheme == uriRight.Scheme && uriLeft.Host == uriRight.Host;
        }
        catch (UriFormatException)
        {
            return false;
        }
    }
}
