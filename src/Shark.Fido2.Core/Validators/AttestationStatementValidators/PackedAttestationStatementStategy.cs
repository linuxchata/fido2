using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Enums;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// 8.2. Packed Attestation Statement Format
/// </summary>
internal class PackedAttestationStatementStategy : IAttestationStatementStategy
{
    private readonly ICryptographyValidator _rsaCryptographyValidator;
    private readonly ICryptographyValidator _ec2CryptographyValidator;

    public PackedAttestationStatementStategy(
        [FromKeyedServices("rsa")] ICryptographyValidator rsaCryptographyValidator,
        [FromKeyedServices("ec2")] ICryptographyValidator ec2CryptographyValidator)
    {
        _rsaCryptographyValidator = rsaCryptographyValidator;
        _ec2CryptographyValidator = ec2CryptographyValidator;
    }

    public ValidatorInternalResult Validate(
        AttestationObjectData attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        var attestationStatement = attestationObjectData.AttestationStatement;
        if (attestationStatement == null)
        {
            throw new ArgumentNullException(nameof(attestationStatement));
        }

        if (attestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException(nameof(attestationStatement), "Attestation statement cannot be read");
        }

        if (!attestationStatementDict.TryGetValue("alg", out var algorithm) || algorithm is not int)
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
        }

        // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;
        if (credentialPublicKey.Algorithm != (int)algorithm)
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm mismatch");
        }

        if (!attestationStatementDict.TryGetValue("sig", out var signature) || signature is not byte[])
        {
            return ValidatorInternalResult.Invalid("Attestation statement signature cannot be read");
        }

        // Verify that sig is a valid signature over the concatenation of authenticatorData and
        // clientDataHash using the credential public key with alg.
        var concatenatedData = GetConcatenatedData(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);

        if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Rsa)
        {
            var isValid = _rsaCryptographyValidator.IsValid(
                concatenatedData, (byte[])signature, credentialPublicKey);

            return ValidatorInternalResult.Valid();
        }
        else if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Ec2)
        {
            var isValid = _ec2CryptographyValidator.IsValid(
                concatenatedData, (byte[])signature, credentialPublicKey);

            return ValidatorInternalResult.Valid();
        }

        return ValidatorInternalResult.Invalid("Invalid signature");
    }

    private static byte[] GetConcatenatedData(byte[] authenticatorData, byte[] clientDataHash)
    {
        var concatenatedData = new byte[authenticatorData.Length + clientDataHash.Length];
        Buffer.BlockCopy(authenticatorData, 0, concatenatedData, 0, authenticatorData.Length);
        Buffer.BlockCopy(clientDataHash, 0, concatenatedData, authenticatorData.Length, clientDataHash.Length);

        return concatenatedData;
    }
}
