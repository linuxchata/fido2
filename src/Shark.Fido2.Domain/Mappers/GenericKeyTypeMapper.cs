using System.Security.Cryptography;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Mappers;

public static class GenericKeyTypeMapper
{
    public static HashAlgorithmName Get(int? keyType, int publicKeyAlgorithm)
    {
        if (keyType == (int)KeyTypeEnum.Rsa)
        {
            return RsaKeyTypeMapper.Get(publicKeyAlgorithm).HashAlgorithmName;
        }
        else if (keyType == (int)KeyTypeEnum.Ec2)
        {
            return Ec2KeyTypeMapper.Get(publicKeyAlgorithm).HashAlgorithmName;
        }
        else
        {
            throw new NotSupportedException("Unsupported key type");
        }
    }
}
