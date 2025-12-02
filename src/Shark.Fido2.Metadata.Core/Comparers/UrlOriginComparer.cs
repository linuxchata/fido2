namespace Shark.Fido2.Metadata.Core.Comparers;

internal static class UrlOriginComparer
{
    internal static bool CompareOrigins(string left, string right)
    {
        try
        {
            Uri uriLeft = new(left);
            Uri uriRight = new(right);

            return string.Equals(uriLeft.Scheme, uriRight.Scheme, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(uriLeft.Host, uriRight.Host, StringComparison.OrdinalIgnoreCase);
        }
        catch (UriFormatException)
        {
            return false;
        }
    }
}
