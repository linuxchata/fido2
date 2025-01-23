using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Core.Validators;

public sealed class Ec2CryptographyValidator : ICryptographyValidator
{
    public bool IsValid(byte[] data, byte[] signature, CredentialPublicKey credentialPublicKey)
    {
        if (!credentialPublicKey.Algorithm.HasValue)
        {
            return false;
        }

        var algorithm = EcdsaKeyTypeMapper.Get(credentialPublicKey.Algorithm.Value);

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

        var sig = ConvertDerToIeeeP1363(signature, ecdsa.KeySize);

        var d1 = ecdsa.VerifyData(data, signature, algorithm.HashAlgorithmName, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var d2 = ecdsa.VerifyData(data, signature, algorithm.HashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence);
        var d3 = ecdsa.VerifyData(data, signature, algorithm.HashAlgorithmName);

        var d4 = ecdsa.VerifyData(data, sig, algorithm.HashAlgorithmName, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var d5 = ecdsa.VerifyData(data, sig, algorithm.HashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence);
        var d6 = ecdsa.VerifyData(data, sig, algorithm.HashAlgorithmName);

        Debug.WriteLine(BitConverter.ToString(signature));
        Debug.WriteLine(BitConverter.ToString(sig));

        return false;
    }

    public static byte[] ConvertDerToIeeeP1363(byte[] derSignature, int keySize)
    {
        // Parse the ASN.1 DER signature
        var reader = new AsnReader(derSignature, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();

        // Extract R and S as integers
        byte[] r = sequence.ReadIntegerBytes().ToArray().Skip(1).ToArray();
        byte[] s = sequence.ReadIntegerBytes().ToArray().Skip(1).ToArray();

        // Ensure there is no extra data in the sequence
        if (sequence.HasData)
            throw new ArgumentException("Invalid DER signature format: extra data found.");

        // Convert R and S to fixed-size, unsigned big-endian format
        int byteLength = keySize / 8;
        byte[] fixedR = new byte[byteLength];
        byte[] fixedS = new byte[byteLength];

        Array.Copy(r, 0, fixedR, byteLength - r.Length, r.Length); // Right-align
        Array.Copy(s, 0, fixedS, byteLength - s.Length, s.Length); // Right-align

        // Concatenate R and S to form IEEE P-1363 format
        byte[] ieeeSignature = new byte[byteLength * 2];
        Array.Copy(fixedR, 0, ieeeSignature, 0, byteLength);
        Array.Copy(fixedS, 0, ieeeSignature, byteLength, byteLength);

        Debug.WriteLine(BitConverter.ToString(fixedR));
        Debug.WriteLine(BitConverter.ToString(fixedS));

        return ieeeSignature;
    }
}
