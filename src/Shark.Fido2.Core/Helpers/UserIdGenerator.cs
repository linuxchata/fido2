using System.Security.Cryptography;
using System.Text;
using Shark.Fido2.Core.Abstractions;

namespace Shark.Fido2.Core.Helpers;

public sealed class UserIdGenerator : IUserIdGenerator
{
    // The user handle of the user account entity. A user handle is an opaque byte sequence
    // with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    private const int MaxUserIdLength = 64;

    public byte[] Get(string? seed = null)
    {
        if (string.IsNullOrWhiteSpace(seed))
        {
            return RandomNumberGenerator.GetBytes(48);
        }

        var userId = Encoding.UTF8.GetBytes(seed);

        return userId.Length <= MaxUserIdLength
            ? userId
            : RandomNumberGenerator.GetBytes(48);
    }
}
