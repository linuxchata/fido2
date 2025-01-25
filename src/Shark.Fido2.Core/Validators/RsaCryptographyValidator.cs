using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Core.Validators;

internal sealed class RsaCryptographyValidator : ICryptographyValidator
{
    public bool IsValid(byte[] data, byte[] signature, X509Certificate2 attestationCertificate, CredentialPublicKey credentialPublicKey)
    {
        if (!credentialPublicKey.Algorithm.HasValue)
        {
            return false;
        }

        var algorithm = RsaKeyTypeMapper.Get(credentialPublicKey.Algorithm.Value);

        var parameters = new RSAParameters
        {
            Modulus = credentialPublicKey.Modulus,
            Exponent = credentialPublicKey.Exponent,
        };

        using var rsa = RSA.Create(parameters);

        return rsa.VerifyData(data, signature, algorithm.HashAlgorithmName, algorithm.Padding!);
    }
}
