using System.Security.Cryptography;

namespace Shark.Fido2.Domain;

public sealed class Rs256Algorithm
{
    public HashAlgorithmName HashAlgorithmName { get; init; }

    public RSASignaturePadding? Padding { get; init; }
}
