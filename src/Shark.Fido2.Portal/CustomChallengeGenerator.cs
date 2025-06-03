using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions;

namespace Shark.Fido2.Portal;

public sealed class CustomChallengeGenerator : IChallengeGenerator
{
    public byte[] Get()
    {
        Span<byte> challengeSpan = stackalloc byte[37];
        RandomNumberGenerator.Fill(challengeSpan);
        return challengeSpan.ToArray();
    }
}
