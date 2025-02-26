using System.Security.Cryptography;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Mappers;

public static class RsaKeyTypeMapper
{
    public static Rs256Algorithm Get(int publicKeyAlgorithm)
    {
        if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Ps256)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA256,
                Padding = RSASignaturePadding.Pss,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.PS384)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA384,
                Padding = RSASignaturePadding.Pss,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.PS512)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA512,
                Padding = RSASignaturePadding.Pss,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Rs256)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA256,
                Padding = RSASignaturePadding.Pkcs1,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.RS1)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA1,
                Padding = RSASignaturePadding.Pkcs1,
            };
        }

        throw new NotSupportedException($"{publicKeyAlgorithm} algorithm is not supported");
    }
}
