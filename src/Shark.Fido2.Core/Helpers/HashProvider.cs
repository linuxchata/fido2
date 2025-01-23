using System.Security.Cryptography;
using System.Text;

namespace Shark.Fido2.Core.Helpers;

internal static class HashProvider
{
    internal static byte[] GetSha256Hash(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentNullException(nameof(value));
        }

        return SHA256.HashData(Encoding.UTF8.GetBytes(value));
    }

    internal static byte[] GetSha256Hash(byte[] value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        return SHA256.HashData(value);
    }
}
