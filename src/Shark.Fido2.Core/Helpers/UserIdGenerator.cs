using System.Security.Cryptography;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;

namespace Shark.Fido2.Core.Helpers;

public sealed class UserIdGenerator : IUserIdGenerator
{
    public byte[] Get(string? seed = null)
    {
        return string.IsNullOrWhiteSpace(seed)
            ? RandomNumberGenerator.GetBytes(32)
            : seed.FromBase64Url();
    }
}
