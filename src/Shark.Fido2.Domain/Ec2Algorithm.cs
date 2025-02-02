using System.Security.Cryptography;

namespace Shark.Fido2.Domain;

public class Ec2Algorithm
{
    public ECCurve Curve { get; set; }

    public HashAlgorithmName HashAlgorithmName { get; set; }
}
