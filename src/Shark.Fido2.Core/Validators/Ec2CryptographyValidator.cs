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

        var algorithmDetails = EcdsaKeyTypeMapper.Get(credentialPublicKey.Algorithm.Value);

        var parameters = new ECParameters
        {
            Q = new ECPoint
            {
                X = credentialPublicKey.XCoordinate,
                Y = credentialPublicKey.YCoordinate,
            },
            Curve = algorithmDetails.Curve, // https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1
        };

        using var ecdsa = ECDsa.Create(parameters);

        return ecdsa.VerifyData(data, signature, algorithmDetails.HashAlgorithmName);
    }
}
