using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Core.Validators
{
    public sealed class RsaCryptographyValidator : ICryptographyValidator
    {
        public bool IsValid(byte[] data, byte[] signature, CredentialPublicKey credentialPublicKey)
        {
            if (!credentialPublicKey.Algorithm.HasValue)
            {
                return false;
            }

            var algorithmDetails = RsaKeyTypeMapper.Get(credentialPublicKey.Algorithm.Value);

            var parameters = new RSAParameters
            {
                Modulus = credentialPublicKey.Modulus,
                Exponent = credentialPublicKey.Exponent,
            };

            using var rsa = RSA.Create(parameters);

            return rsa.VerifyData(data, signature, algorithmDetails.HashAlgorithmName, algorithmDetails.Padding);
        }
    }
}
