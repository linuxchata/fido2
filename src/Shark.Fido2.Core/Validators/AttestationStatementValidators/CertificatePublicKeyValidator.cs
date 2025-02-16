using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

internal sealed class CertificatePublicKeyValidator : ICertificatePublicKeyValidator
{
    private const string CertificatePublicKeyIsNotValid = "Certificate public key is not valid";

    public ValidatorInternalResult Validate(
        X509Certificate2 attestationCertificate,
        CredentialPublicKey credentialPublicKey)
    {
        bool isValid;
        if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Rsa)
        {
            var rsaPublicKey = attestationCertificate.GetRSAPublicKey();
            var parameters = rsaPublicKey?.ExportParameters(false);

            isValid = BytesArrayComparer.CompareNullable(credentialPublicKey.Modulus, parameters?.Modulus) &&
                BytesArrayComparer.CompareNullable(credentialPublicKey.Exponent, parameters?.Exponent);
        }
        else if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Ec2)
        {
            var ecdsaPublicKey = attestationCertificate.GetECDsaPublicKey();
            var parameters = ecdsaPublicKey?.ExportParameters(false);

            isValid = BytesArrayComparer.CompareNullable(credentialPublicKey.XCoordinate, parameters?.Q.X) &&
                BytesArrayComparer.CompareNullable(credentialPublicKey.YCoordinate, parameters?.Q.Y);
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type {credentialPublicKey.KeyType}");
        }

        return isValid ? ValidatorInternalResult.Valid() : ValidatorInternalResult.Invalid(CertificatePublicKeyIsNotValid);
    }
}
