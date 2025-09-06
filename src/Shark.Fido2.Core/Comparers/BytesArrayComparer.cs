using System.Security.Cryptography;

namespace Shark.Fido2.Core.Comparers;

public static class BytesArrayComparer
{
    public static bool CompareNullable(byte[]? expected, byte[]? actual)
    {
        if (expected == null && actual == null)
        {
            return true;
        }

        if (expected == null || actual == null)
        {
            return false;
        }

        // Compare two byte arrays for equality without leaking timing information.
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    public static bool CompareAsSpan(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        return expected.SequenceEqual(actual);
    }
}
