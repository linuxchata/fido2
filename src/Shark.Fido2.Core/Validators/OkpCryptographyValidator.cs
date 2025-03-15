using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators;

internal sealed class OkpCryptographyValidator : IOkpCryptographyValidator
{
    public bool IsValid(
        byte[] data,
        byte[] signature,
        CredentialPublicKey credentialPublicKey)
    {
        if (credentialPublicKey.Algorithm == (int)PublicKeyAlgorithm.EdDsa &&
            credentialPublicKey.Curve == (int)EllipticCurveKey.Ed25519)
        {
            var parameters = new Ed25519PublicKeyParameters(credentialPublicKey.XCoordinate, 0);
            var signer = new Ed25519Signer();
            signer.Init(false, parameters);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }
        else
        {
            throw new NotSupportedException(
                $"Algorithm {credentialPublicKey.Algorithm} with elliptic curve key {credentialPublicKey.Curve} is not supported");
        }
    }
}
