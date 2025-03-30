using System.Security.Cryptography;

namespace Shark.Fido2.Domain;

public sealed class Ec2Algorithm
{
    public ECCurve Curve { get; init; }

    public HashAlgorithmName HashAlgorithmName { get; init; }
}
