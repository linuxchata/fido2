using System;
using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions;

namespace Shark.Fido2.Core
{
    public sealed class ChallengeGenerator : IChallengeGenerator
    {
        public string Get()
        {
            var challengeBytes = new byte[16];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(challengeBytes);
            return Convert.ToBase64String(challengeBytes);
        }
    }
}
