using System;
using System.Security.Cryptography;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Mappers
{
    public static class EcdsaKeyTypeMapper
    {
        public static EcdsaAlgorithm Get(int publicKeyAlgorithm)
        {
            if (publicKeyAlgorithm == (int)PublicKeyAlgorithm.Es256)
            {
                return new EcdsaAlgorithm
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    HashAlgorithmName = HashAlgorithmName.SHA256,
                };
            }

            throw new ArgumentException();
        }
    }
}
