﻿using System;
using System.Security.Cryptography;
using System.Text;

namespace Shark.Fido2.Core.Helpers
{
    internal static class HashProvider
    {
        internal static byte[] GetSha256Hash(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentNullException(nameof(value));
            }

            using var sha256 = SHA256.Create();

            return sha256.ComputeHash(Encoding.UTF8.GetBytes(value));
        }

        internal static byte[] GetSha256Hash(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            using var sha256 = SHA256.Create();

            return sha256.ComputeHash(value);
        }
    }
}
