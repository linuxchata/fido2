using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Enums;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators;

internal class SignatureAttestationStatementValidator : ISignatureAttestationStatementValidator
{
    private const string Signature = "sig";

    private readonly ICryptographyValidator _rsaCryptographyValidator;
    private readonly ICryptographyValidator _ec2CryptographyValidator;

    public SignatureAttestationStatementValidator(
        [FromKeyedServices("rsa")] ICryptographyValidator rsaCryptographyValidator,
        [FromKeyedServices("ec2")] ICryptographyValidator ec2CryptographyValidator)
    {
        _rsaCryptographyValidator = rsaCryptographyValidator;
        _ec2CryptographyValidator = ec2CryptographyValidator;
    }

    public ValidatorInternalResult Validate(
        byte[] authenticatorRawData,
        byte[] clientDataHash,
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey)
    {
        // Verify that sig is a valid signature over the concatenation of authenticatorData and
        // clientDataHash using the credential public key with alg.
        if (!attestationStatementDict.TryGetValue(Signature, out var signature) || signature is not byte[])
        {
            return ValidatorInternalResult.Invalid("Attestation statement signature cannot be read");
        }

        var concatenatedData = GetConcatenatedData(authenticatorRawData, clientDataHash);

        if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Rsa)
        {
            _rsaCryptographyValidator.IsValid(concatenatedData, (byte[])signature, credentialPublicKey);
        }
        else if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Ec2)
        {
            _ec2CryptographyValidator.IsValid(concatenatedData, (byte[])signature, credentialPublicKey);
        }

        return ValidatorInternalResult.Valid();
    }

    private static byte[] GetConcatenatedData(byte[] authenticatorData, byte[] clientDataHash)
    {
        var concatenatedData = new byte[authenticatorData.Length + clientDataHash.Length];
        Buffer.BlockCopy(authenticatorData, 0, concatenatedData, 0, authenticatorData.Length);
        Buffer.BlockCopy(clientDataHash, 0, concatenatedData, authenticatorData.Length, clientDataHash.Length);

        return concatenatedData;
    }
}
