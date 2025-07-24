using System.Security.Cryptography;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Mappers;

public static class GenericKeyTypeMapper
{
    public static (KeyType, HashAlgorithmName) Get(int coseAlgorithm)
    {
        var rs256Algorithm = RsaKeyTypeMapper.Get(coseAlgorithm);
        if (rs256Algorithm != null)
        {
            return (KeyType.Rsa, rs256Algorithm.HashAlgorithmName);
        }

        var ec2Algorithm = Ec2KeyTypeMapper.Get(coseAlgorithm);
        if (ec2Algorithm != null)
        {
            return (KeyType.Ec2, ec2Algorithm.HashAlgorithmName);
        }

        throw new NotSupportedException($"{coseAlgorithm} algorithm is not supported");
    }
}
