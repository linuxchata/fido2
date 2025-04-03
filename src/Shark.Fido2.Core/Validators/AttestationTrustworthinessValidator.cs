using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Metadata.Core.Domain;
using Shark.Fido2.Metadata.Core.Domain.Constants;

namespace Shark.Fido2.Core.Validators;

internal class AttestationTrustworthinessValidator : IAttestationTrustworthinessValidator
{
    private readonly TimeProvider _timeProvider;
    private readonly Fido2Configuration _configuration;

    public AttestationTrustworthinessValidator(TimeProvider timeProvider, IOptions<Fido2Configuration> options)
    {
        _timeProvider = timeProvider;
        _configuration = options.Value;
    }

    public ValidatorInternalResult Validate(
        AttestationStatementInternalResult attestationStatementResult,
        MetadataPayloadItem? authenticatorMetadata)
    {
        if (attestationStatementResult == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement result cannot be null");
        }

        // If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
        if (attestationStatementResult.AttestationType == AttestationTypeEnum.None)
        {
            return _configuration.AllowNoneAttestation
                ? ValidatorInternalResult.Valid()
                : ValidatorInternalResult.Invalid("None attestation type is not allowed under current policy");
        }

        // If self attestation was used, verify that Self attestation is acceptable under Relying Party policy.
        if (attestationStatementResult.AttestationType == AttestationTypeEnum.Self)
        {
            return _configuration.AllowSelfAttestation
                ? ValidatorInternalResult.Valid()
                : ValidatorInternalResult.Invalid("Self attestation type is not allowed under current policy");
        }

        // Self attestation cannot contains full attestation (trust path)
        if (authenticatorMetadata?.AttestationTypes?.Length == 1 &&
            authenticatorMetadata.AttestationTypes.First() == AttestationType.BasicSurrogate &&
            attestationStatementResult.TrustPath?.Length > 0)
        {
            return ValidatorInternalResult.Invalid(
                $"{AttestationType.BasicSurrogate} (self) attestation type cannot have trust path");
        }

        // Otherwise, use the X.509 certificates returned as the attestation trust path from the verification
        // procedure to verify that the attestation public key either correctly chains up to an acceptable root
        // certificate, or is itself an acceptable certificate.
        if (attestationStatementResult.TrustPath == null || attestationStatementResult.TrustPath.Length == 0)
        {
            return ValidatorInternalResult.Invalid(
                $"Trust path is required for {attestationStatementResult.AttestationType} attestation type");
        }

        var result = ValidateTrustPath(attestationStatementResult.TrustPath);

        return result;
    }

    private ValidatorInternalResult ValidateTrustPath(X509Certificate2[] certificates)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.ChainPolicy.VerificationTime = _timeProvider.GetLocalNow().DateTime;

        var leafCertificate = certificates.First();

        foreach (var certificate in certificates.Skip(1))
        {
            if (certificate.Subject == certificate.Issuer)
            {
                // If trust path contains a root certificate (full chain), the server should return error
                return ValidatorInternalResult.Invalid("Trust path contains a root certificate");
            }
            else
            {
                // Intermediate certificate
                chain.ChainPolicy.ExtraStore.Add(certificate);
            }
        }

        var isValid = chain.Build(leafCertificate);
        if (!isValid)
        {
            return ValidatorInternalResult.Invalid(string.Join('.', chain.ChainStatus));
        }

        return ValidatorInternalResult.Valid();
    }
}
