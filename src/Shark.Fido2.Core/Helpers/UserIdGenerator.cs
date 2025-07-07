using System.Security.Cryptography;
using System.Text;
using Shark.Fido2.Core.Abstractions;

namespace Shark.Fido2.Core.Helpers;

public sealed class UserIdGenerator : IUserIdGenerator
{
    public byte[] Get(string? seed = null)
    {
        if (string.IsNullOrWhiteSpace(seed))
        {
            return RandomNumberGenerator.GetBytes(48);
        }

        var userId = Encoding.UTF8.GetBytes(seed);

        return userId.Length <= 64
            ? userId
            : RandomNumberGenerator.GetBytes(48);
    }
}
