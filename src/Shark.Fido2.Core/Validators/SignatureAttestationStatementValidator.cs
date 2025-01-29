using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Enums;
using Shark.Fido2.Core.Helpers;
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
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2 attestationCertificate,
        byte[] authenticatorRawData,
        byte[] clientDataHash)
    {
        // Verify that sig is a valid signature over the concatenation of authenticatorData and
        // clientDataHash using the credential public key with alg.
        if (!attestationStatementDict.TryGetValue(Signature, out var signature) || signature is not byte[])
        {
            return ValidatorInternalResult.Invalid("Attestation statement signature cannot be read");
        }

        var concatenatedData = BytesArrayHelper.Concatenate(authenticatorRawData, clientDataHash);

        bool isValid;
        if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Rsa)
        {
            isValid = _rsaCryptographyValidator.IsValid(
                concatenatedData,
                (byte[])signature,
                attestationCertificate,
                credentialPublicKey);
        }
        else if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Ec2)
        {
            isValid = _ec2CryptographyValidator.IsValid(
                concatenatedData,
                (byte[])signature,
                attestationCertificate,
                credentialPublicKey);
        }
        else
        {
            throw new NotSupportedException("Unsupported key type");
        }

        if (!isValid)
        {
            return ValidatorInternalResult.Invalid("Attestation statement signature is not valid");
        }

        return ValidatorInternalResult.Valid();
    }
}
