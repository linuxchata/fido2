using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions;

namespace Shark.Fido2.Core.Helpers;

public sealed class ChallengeGenerator : IChallengeGenerator
{
    public byte[] Get()
    {
        var challengeBytes = new byte[16];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(challengeBytes);
        return challengeBytes;
    }
}
