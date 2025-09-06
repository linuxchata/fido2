using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions;

namespace Shark.Fido2.Core.Helpers;

public sealed class ChallengeGenerator : IChallengeGenerator
{
    // See: https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
    // In order to prevent replay attacks, the challenges MUST contain enough entropy to make guessing them
    // infeasible. Challenges SHOULD therefore be at least 16 bytes long.
    // However, current implementation uses 32 bytes (256 bits) for enhanced security.
    private const int ChallengeLengthInBytes = 32;

    public byte[] Get()
    {
        var challengeBytes = new byte[ChallengeLengthInBytes];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(challengeBytes);
        return challengeBytes;
    }
}
