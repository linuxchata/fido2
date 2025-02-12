using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

internal class SignatureAttestationStatementValidator : ISignatureAttestationStatementValidator
{
    private const string SignatureCannotBeReadErrorMessage = "Attestation statement signature cannot be read";
    private const string SignatureIsNotValid = "Attestation statement signature is not valid";

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
        byte[] data,
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2? attestationCertificate = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(attestationStatementDict);
        ArgumentNullException.ThrowIfNull(credentialPublicKey);

        if (!attestationStatementDict.TryGetValue(AttestationStatement.Signature, out var signature) ||
            signature is not byte[])
        {
            return ValidatorInternalResult.Invalid(SignatureCannotBeReadErrorMessage);
        }

        bool isValid;
        if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Rsa)
        {
            isValid = _rsaCryptographyValidator.IsValid(
                data,
                (byte[])signature,
                credentialPublicKey,
                attestationCertificate);
        }
        else if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Ec2)
        {
            isValid = _ec2CryptographyValidator.IsValid(
                data,
                (byte[])signature,
                credentialPublicKey,
                attestationCertificate);
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type {credentialPublicKey.KeyType}");
        }

        if (!isValid)
        {
            return ValidatorInternalResult.Invalid(SignatureIsNotValid);
        }

        return ValidatorInternalResult.Valid();
    }

    public ValidatorInternalResult Validate(
        byte[] data,
        Dictionary<string, object> attestationStatementDict,
        KeyTypeEnum keyType,
        int algorithm,
        X509Certificate2 attestationCertificate)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(attestationStatementDict);
        ArgumentNullException.ThrowIfNull(attestationCertificate);

        if (!attestationStatementDict.TryGetValue(AttestationStatement.Signature, out var signature) ||
            signature is not byte[])
        {
            return ValidatorInternalResult.Invalid(SignatureCannotBeReadErrorMessage);
        }

        bool isValid;
        if (keyType == KeyTypeEnum.Rsa)
        {
            isValid = _rsaCryptographyValidator.IsValid(
                data,
                (byte[])signature,
                algorithm,
                attestationCertificate);
        }
        else if (keyType == KeyTypeEnum.Ec2)
        {
            isValid = _ec2CryptographyValidator.IsValid(
                data,
                (byte[])signature,
                algorithm,
                attestationCertificate);
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type {keyType}");
        }

        if (!isValid)
        {
            return ValidatorInternalResult.Invalid(SignatureIsNotValid);
        }

        return ValidatorInternalResult.Valid();
    }
}
