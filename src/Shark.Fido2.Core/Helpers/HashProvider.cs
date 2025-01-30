using System.Security.Cryptography;
using System.Text;

namespace Shark.Fido2.Core.Helpers;

internal static class HashProvider
{
    internal static byte[] GetHash(byte[] value, HashAlgorithmName hashAlgorithmName)
    {
        ArgumentNullException.ThrowIfNull(value);

        return hashAlgorithmName.Name switch
        {
            "SHA1" => SHA1.HashData(value),
            "SHA384" => SHA384.HashData(value),
            "SHA256" => SHA256.HashData(value),
            "SHA512" => SHA512.HashData(value),
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithmName.Name} is not supported"),
        };
    }

    internal static byte[] GetSha256Hash(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentNullException(nameof(value));
        }

        return GetHash(Encoding.UTF8.GetBytes(value), HashAlgorithmName.SHA256);
    }

    internal static byte[] GetSha256Hash(byte[] value)
    {
        return GetHash(value, HashAlgorithmName.SHA256);
    }
}
