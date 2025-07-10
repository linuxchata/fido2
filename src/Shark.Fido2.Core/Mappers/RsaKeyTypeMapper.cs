using System.Security.Cryptography;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Mappers;

public static class RsaKeyTypeMapper
{
    public static Rs256Algorithm? Get(int coseAlgorithm)
    {
        if (coseAlgorithm == (int)CoseAlgorithm.Ps256)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA256,
                Padding = RSASignaturePadding.Pss,
            };
        }
        else if (coseAlgorithm == (int)CoseAlgorithm.Ps384)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA384,
                Padding = RSASignaturePadding.Pss,
            };
        }
        else if (coseAlgorithm == (int)CoseAlgorithm.Ps512)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA512,
                Padding = RSASignaturePadding.Pss,
            };
        }
        else if (coseAlgorithm == (int)CoseAlgorithm.Rs256)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA256,
                Padding = RSASignaturePadding.Pkcs1,
            };
        }
        else if (coseAlgorithm == (int)CoseAlgorithm.Rs384)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA384,
                Padding = RSASignaturePadding.Pkcs1,
            };
        }
        else if (coseAlgorithm == (int)CoseAlgorithm.Rs512)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA512,
                Padding = RSASignaturePadding.Pkcs1,
            };
        }
        else if (coseAlgorithm == (int)CoseAlgorithm.Rs1)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA1,
                Padding = RSASignaturePadding.Pkcs1,
            };
        }

        return null;
    }
}
