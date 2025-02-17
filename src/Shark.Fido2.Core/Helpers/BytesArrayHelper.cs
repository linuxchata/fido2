﻿﻿﻿namespace Shark.Fido2.Core.Helpers;

public static class BytesArrayHelper
{
    public static byte[] Concatenate(byte[]? left, byte[]? right)
    {
        if (left == null && right == null)
        {
            return [];
        }

        if (left == null)
        {
            return right != null ? (byte[])right.Clone() : [];
        }

        if (right == null)
        {
            return (byte[])left.Clone();
        }

        var concatenatedData = new byte[left.Length + right.Length];
        
        Buffer.BlockCopy(left, 0, concatenatedData, 0, left.Length);
        Buffer.BlockCopy(right, 0, concatenatedData, left.Length, right.Length);

        return concatenatedData;
    }
}
