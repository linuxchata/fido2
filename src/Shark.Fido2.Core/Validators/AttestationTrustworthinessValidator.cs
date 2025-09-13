using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators;

internal class AttestationTrustworthinessValidator : IAttestationTrustworthinessValidator
{
    private readonly IAttestationTrustAnchorValidator _attestationTrustAnchorValidator;
    private readonly TimeProvider _timeProvider;
    private readonly Fido2Configuration _configuration;
    private readonly ILogger<AttestationTrustworthinessValidator> _logger;

    public AttestationTrustworthinessValidator(
        IAttestationTrustAnchorValidator attestationTrustAnchorValidator,
        TimeProvider timeProvider,
        IOptions<Fido2Configuration> options,
        ILogger<AttestationTrustworthinessValidator> logger)
    {
        _attestationTrustAnchorValidator = attestationTrustAnchorValidator;
        _timeProvider = timeProvider;
        _configuration = options.Value;
        _logger = logger;
    }

    public async Task<ValidatorInternalResult> Validate(
        AuthenticatorData authenticatorData,
        AttestationStatementInternalResult attestationStatementResult,
        CancellationToken cancellationToken)
    {
        if (attestationStatementResult == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement result cannot be null");
        }

        // If no attestation was provided, verify that None attestation is allowed under Relying Party policy.
        if (attestationStatementResult.AttestationType == Domain.Enums.AttestationType.None)
        {
            if (_configuration.AllowNoneAttestation)
            {
                _logger.LogDebug("None attestation type is allowed under current policy");
            }

            return _configuration.AllowNoneAttestation
                ? ValidatorInternalResult.Valid()
                : ValidatorInternalResult.Invalid("None attestation type is not allowed under current policy");
        }

        // If self attestation was used, verify that Self attestation is allowed under Relying Party policy.
        if (attestationStatementResult.AttestationType == Domain.Enums.AttestationType.Self)
        {
            if (_configuration.AllowSelfAttestation)
            {
                _logger.LogDebug("Self attestation type is allowed under current policy");
            }

            return _configuration.AllowSelfAttestation
                ? ValidatorInternalResult.Valid()
                : ValidatorInternalResult.Invalid("Self attestation type is not allowed under current policy");
        }

        // If only basic surrogate attestation is supported by the authenticator, verify that attestation does not
        // contain a full trust path.
        var result = await _attestationTrustAnchorValidator.ValidateBasicAttestation(
            authenticatorData,
            attestationStatementResult.TrustPath,
            cancellationToken);
        if (!result.IsValid)
        {
            return result;
        }

        // Otherwise, use the X.509 certificates returned as the attestation trust path from the verification
        // procedure to verify that the attestation public key either correctly chains up to an acceptable root
        // certificate, or is itself an acceptable certificate.
        if (attestationStatementResult.TrustPath == null || attestationStatementResult.TrustPath.Length == 0)
        {
            return ValidatorInternalResult.Invalid(
                $"Trust path is required for {attestationStatementResult.AttestationType} attestation type");
        }

        result = ValidateTrustPath(attestationStatementResult);

        _logger.LogDebug("Attestation trust path is valid");

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

        if (!chain.Build(leafCertificate))
        {
            var statuses = chain.ChainStatus.Select(a => a.StatusInformation);
            return ValidatorInternalResult.Invalid(string.Join(' ', statuses.ToList()));
        }

        return ValidatorInternalResult.Valid();
    }

    private static X509VerificationFlags GetVerificationFlags(string attestationFormat)
    {
        if (string.Equals(
            attestationFormat,
            AttestationStatementFormatIdentifier.AndroidKey,
            StringComparison.OrdinalIgnoreCase))
        {
            // Some Android devices may generate an attestation certificate with a default date of January 1, 1970.
            // See https://source.android.com/docs/security/features/keystore/attestation#tbscertificate-sequence.
            return X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.AllowUnknownCertificateAuthority;
        }
        else if (string.Equals(
            attestationFormat,
            AttestationStatementFormatIdentifier.AndroidSafetyNet,
            StringComparison.OrdinalIgnoreCase))
        {
            // The certificate used by Android SafetyNet attestation, namely 'GlobalSign Root CA - R2', expired on
            // Dec 15, 2021, at 08:00:00, so allowing an unknown certificate authority for backward compatibility.
            // See https://crt.sh/?id=14.
            return X509VerificationFlags.AllowUnknownCertificateAuthority;
        }
        else if (string.Equals(
            attestationFormat,
            AttestationStatementFormatIdentifier.Apple,
            StringComparison.OrdinalIgnoreCase))
        {
            return X509VerificationFlags.NoFlag;
        }

        return X509VerificationFlags.AllowUnknownCertificateAuthority;
    }
}
