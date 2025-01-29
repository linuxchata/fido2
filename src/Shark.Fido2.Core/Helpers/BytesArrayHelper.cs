namespace Shark.Fido2.Core.Helpers;

public static class BytesArrayHelper
{
    public static byte[] Concatenate(byte[] left, byte[] right)
    {
        var concatenatedData = new byte[left.Length + right.Length];
        Buffer.BlockCopy(left, 0, concatenatedData, 0, left.Length);
        Buffer.BlockCopy(right, 0, concatenatedData, left.Length, right.Length);

        return concatenatedData;
    }
}
