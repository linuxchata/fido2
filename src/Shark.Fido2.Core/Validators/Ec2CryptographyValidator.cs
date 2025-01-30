using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Core.Validators;

internal sealed class Ec2CryptographyValidator : ICryptographyValidator
{
    public bool IsValid(byte[] data, byte[] signature, X509Certificate2 attestationCertificate, CredentialPublicKey credentialPublicKey)
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

            var signatureIeeeP1363 = ConvertDerToIeeeP1363(signature, ecdsa.KeySize);

            return ecdsa.VerifyData(data, signature, algorithm.HashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence);
        }
    }

    private static byte[] ConvertDerToIeeeP1363(byte[] derSignature, int keySize)
    {
        // Parse the ASN.1 DER signature
        var reader = new AsnReader(derSignature, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();

        // Extract R and S as integers
        var r = sequence.ReadIntegerBytes()[1..].ToArray();
        var s = sequence.ReadIntegerBytes()[1..].ToArray();

        // Ensure there is no extra data in the sequence
        if (sequence.HasData)
        {
            throw new ArgumentException("Invalid DER signature format");
        }

        // Convert R and S to fixed-size, unsigned big-endian format
        var byteLength = keySize / 8;
        var fixedR = new byte[byteLength];
        var fixedS = new byte[byteLength];

        Array.Copy(r, 0, fixedR, byteLength - r.Length, r.Length); // Right-align
        Array.Copy(s, 0, fixedS, byteLength - s.Length, s.Length); // Right-align

        // Concatenate R and S to form IEEE P-1363 format
        var ieeeSignature = new byte[byteLength * 2];
        Array.Copy(fixedR, 0, ieeeSignature, 0, byteLength);
        Array.Copy(fixedS, 0, ieeeSignature, byteLength, byteLength);

        Debug.WriteLine(BitConverter.ToString(fixedR));
        Debug.WriteLine(BitConverter.ToString(fixedS));

        return ieeeSignature;
    }
}
