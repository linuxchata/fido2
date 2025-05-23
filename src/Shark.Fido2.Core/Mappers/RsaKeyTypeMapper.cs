﻿using System.Security.Cryptography;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Mappers;

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
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Ps384)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA384,
                Padding = RSASignaturePadding.Pss,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Ps512)
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
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Rs384)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA384,
                Padding = RSASignaturePadding.Pkcs1,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Rs512)
        {
            return new Rs256Algorithm
            {
                HashAlgorithmName = HashAlgorithmName.SHA512,
                Padding = RSASignaturePadding.Pkcs1,
            };
        }
        else if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Rs1)
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
