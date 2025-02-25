using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators;

internal class AttestationTrustworthinessValidator : IAttestationTrustworthinessValidator
{
    private readonly Fido2Configuration _configuration;

    public AttestationTrustworthinessValidator(IOptions<Fido2Configuration> options)
    {
        _configuration = options.Value;
    }

    public ValidatorInternalResult Validate(AttestationStatementInternalResult attestationStatementResult)
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

        // Otherwise, use the X.509 certificates returned as the attestation trust path from the verification
        // procedure to verify that the attestation public key either correctly chains up to an acceptable root
        // certificate, or is itself an acceptable certificate.
        if (attestationStatementResult.TrustPath == null || !attestationStatementResult.TrustPath.Any())
        {
            return ValidatorInternalResult.Invalid(
                $"Trust path is required for {attestationStatementResult.AttestationType} attestation type");
        }

        // TODO: Implement trust path verification against acceptable root certificates

        return ValidatorInternalResult.Valid();
    }
}
