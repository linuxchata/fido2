using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators;

internal sealed class RsaCryptographyValidator : IRsaCryptographyValidator
{
    public bool IsValid(
        byte[] data,
        byte[] signature,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2? attestationCertificate = null)
    {
        var rs256Algorithm = RsaKeyTypeMapper.Get(credentialPublicKey.Algorithm);

        if (attestationCertificate != null)
        {
            return IsValidAttestationCertificate(data, signature, rs256Algorithm, attestationCertificate);
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

    public bool IsValid(byte[] data, byte[] signature, int algorithm, X509Certificate2 attestationCertificate)
    {
        if (attestationCertificate == null)
        {
            return false;
        }

        var rs256Algorithm = RsaKeyTypeMapper.Get(algorithm);

        return IsValidAttestationCertificate(data, signature, rs256Algorithm, attestationCertificate);
    }

    private static bool IsValidAttestationCertificate(
        byte[] data,
        byte[] signature,
        Rs256Algorithm algorithm,
        X509Certificate2 attestationCertificate)
    {
        using var rsa = attestationCertificate.GetRSAPublicKey() ??
            throw new ArgumentException("Certificate does not have a RSA public key");

        return rsa!.VerifyData(data, signature, algorithm.HashAlgorithmName, algorithm.Padding!);
    }
}
