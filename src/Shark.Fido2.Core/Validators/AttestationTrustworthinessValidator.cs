using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Metadata.Core.Domain;

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
        MetadataPayloadItem? metadataPayloadItem)
    {
        if (attestationStatementResult == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement result cannot be null");
        }

        // If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
        if (attestationStatementResult.AttestationType == Domain.Enums.AttestationType.None)
        {
            return _configuration.AllowNoneAttestation
                ? ValidatorInternalResult.Valid()
                : ValidatorInternalResult.Invalid("None attestation type is not allowed under current policy");
        }

        // If self attestation was used, verify that Self attestation is acceptable under Relying Party policy.
        if (attestationStatementResult.AttestationType == Domain.Enums.AttestationType.Self)
        {
            return _configuration.AllowSelfAttestation
                ? ValidatorInternalResult.Valid()
                : ValidatorInternalResult.Invalid("Self attestation type is not allowed under current policy");
        }

        // Self attestation cannot contains full attestation (trust path)
        if (metadataPayloadItem?.AttestationTypes?.Length == 1 &&
            metadataPayloadItem.AttestationTypes[0] == Metadata.Core.Domain.Constants.AttestationType.BasicSurrogate &&
            attestationStatementResult.TrustPath?.Length > 0)
        {
            return ValidatorInternalResult.Invalid(
                $"{Metadata.Core.Domain.Constants.AttestationType.BasicSurrogate} (self) attestation type cannot have trust path");
        }

        // Otherwise, use the X.509 certificates returned as the attestation trust path from the verification
        // procedure to verify that the attestation public key either correctly chains up to an acceptable root
        // certificate, or is itself an acceptable certificate.
        if (attestationStatementResult.TrustPath == null || attestationStatementResult.TrustPath.Length == 0)
        {
            return ValidatorInternalResult.Invalid(
                $"Trust path is required for {attestationStatementResult.AttestationType} attestation type");
        }

        var result = ValidateTrustPath(attestationStatementResult);

        return result;
    }

    private ValidatorInternalResult ValidateTrustPath(AttestationStatementInternalResult attestationStatementResult)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = GetVerificationFlags(attestationStatementResult.AttestationStatementFormat);
        chain.ChainPolicy.VerificationTime = _timeProvider.GetLocalNow().DateTime;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        var certificates = attestationStatementResult.TrustPath!;
        var leafCertificate = certificates[0];

        foreach (var certificate in certificates[1..])
        {
            if (certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData))
            {
                // Root certificate
                chain.ChainPolicy.CustomTrustStore.Add(certificate);
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
            var statuses = chain.ChainStatus.Select(a => a.StatusInformation);
            return ValidatorInternalResult.Invalid(string.Join(' ', statuses.ToList()));
        }

        return ValidatorInternalResult.Valid();
    }

    private static X509VerificationFlags GetVerificationFlags(string attestationStatementFormat)
    {
        // Some Android devices may generate an attestation certificate with a default date of January 1, 1970.
        // See https://source.android.com/docs/security/features/keystore/attestation#tbscertificate-sequence.
        if (string.Equals(
            attestationStatementFormat,
            AttestationStatementFormatIdentifier.AndroidKey,
            StringComparison.OrdinalIgnoreCase))
        {
            return X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.AllowUnknownCertificateAuthority;
        }

        return X509VerificationFlags.AllowUnknownCertificateAuthority;
    }
}
