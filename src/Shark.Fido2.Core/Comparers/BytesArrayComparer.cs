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

        return Compare(expected, actual);
    }

    public static bool Compare(byte[] expected, byte[] actual)
    {
        if (expected == actual)
        {
            return true;
        }

        if (expected.Length != actual.Length)
        {
            return false;
        }

        for (var i = 0; i < expected.Length; i++)
        {
            if (expected[i] != actual[i])
            {
                return false;
            }
        }

        return true;
    }

    public static bool CompareAsSpan(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        return expected.SequenceEqual(actual);
    }
}
