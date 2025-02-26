using System.Security.Cryptography;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Mappers;

public static class Ec2KeyTypeMapper
{
    public static Ec2Algorithm Get(int publicKeyAlgorithm)
    {
        if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Es256)
        {
            return new Ec2Algorithm
            {
                Curve = ECCurve.NamedCurves.nistP256,
                HashAlgorithmName = HashAlgorithmName.SHA256,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Es384)
        {
            return new Ec2Algorithm
            {
                Curve = ECCurve.NamedCurves.nistP384,
                HashAlgorithmName = HashAlgorithmName.SHA384,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Es512)
        {
            return new Ec2Algorithm
            {
                Curve = ECCurve.NamedCurves.nistP521,
                HashAlgorithmName = HashAlgorithmName.SHA512,
            };
        }

        throw new NotSupportedException($"{publicKeyAlgorithm} algorithm is not supported");
    }
}
