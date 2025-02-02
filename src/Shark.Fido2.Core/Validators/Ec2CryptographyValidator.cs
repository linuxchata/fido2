using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Core.Validators;

internal sealed class Ec2CryptographyValidator : ICryptographyValidator
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

        var algorithm = Ec2KeyTypeMapper.Get(credentialPublicKey.Algorithm.Value);

        if (attestationCertificate != null)
        {
            using var ecdsa = attestationCertificate.GetECDsaPublicKey() ??
                throw new ArgumentException("Certificate does not have an ECDsa public key");

            return ecdsa!.VerifyData(data, signature, algorithm.HashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence);
        }
        else
        {
            var parameters = new ECParameters
            {
                Q = new ECPoint
                {
                    X = credentialPublicKey.XCoordinate,
                    Y = credentialPublicKey.YCoordinate,
                },
                Curve = algorithm.Curve, // https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1
            };

            using var ecdsa = ECDsa.Create(parameters);

            return ecdsa.VerifyData(data, signature, algorithm.HashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence);
        }
    }

    public bool IsValid(byte[] data, byte[] signature, X509Certificate2 attestationCertificate, int algorithm)
    {
        if (attestationCertificate == null)
        {
            return false;
        }

        var ec2Algorithm = Ec2KeyTypeMapper.Get(algorithm);

        throw new NotImplementedException();
    }
}
