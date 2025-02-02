using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Core.Validators;

internal sealed class RsaCryptographyValidator : ICryptographyValidator
{
    public bool IsValid(
        byte[] data,
        byte[] signature,
        X509Certificate2 attestationCertificate,
        CredentialPublicKey credentialPublicKey)
    {
        if (!credentialPublicKey.Algorithm.HasValue)
        {
            return false;
        }

        var rs256Algorithm = RsaKeyTypeMapper.Get(credentialPublicKey.Algorithm.Value);

        if (attestationCertificate != null)
        {
            return IsValidAttestationCertificate(data, signature, attestationCertificate, rs256Algorithm);
        }
        else
        {
            var parameters = new RSAParameters
            {
                Modulus = credentialPublicKey.Modulus,
                Exponent = credentialPublicKey.Exponent,
            };

            using var rsa = RSA.Create(parameters);

            return rsa.VerifyData(data, signature, rs256Algorithm.HashAlgorithmName, rs256Algorithm.Padding!);
        }
    }

    public bool IsValid(byte[] data, byte[] signature, X509Certificate2 attestationCertificate, int algorithm)
    {
        if (attestationCertificate == null)
        {
            return false;
        }

        var rs256Algorithm = RsaKeyTypeMapper.Get(algorithm);

        return IsValidAttestationCertificate(data, signature, attestationCertificate, rs256Algorithm);
    }

    private static bool IsValidAttestationCertificate(
        byte[] data,
        byte[] signature,
        X509Certificate2 attestationCertificate,
        Rs256Algorithm algorithm)
    {
        using var rsa = attestationCertificate.GetRSAPublicKey() ??
            throw new ArgumentException("Certificate does not have a RSA public key");

        return rsa!.VerifyData(data, signature, algorithm.HashAlgorithmName, algorithm.Padding!);
    }
}
