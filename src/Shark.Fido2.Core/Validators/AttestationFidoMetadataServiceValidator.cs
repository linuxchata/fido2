using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Domain.Constants;

namespace Shark.Fido2.Core.Validators;

internal class AttestationFidoMetadataServiceValidator : IAttestationTrustAnchorValidator
{
    private readonly IMetadataCachedService _metadataService;
    private readonly Fido2Configuration _configuration;
    private readonly ILogger<AttestationFidoMetadataServiceValidator> _logger;

    public AttestationFidoMetadataServiceValidator(
        IMetadataCachedService metadataService,
        IOptions<Fido2Configuration> options,
        ILogger<AttestationFidoMetadataServiceValidator> logger)
    {
        _metadataService = metadataService;
        _configuration = options.Value;
        _logger = logger;
    }

    public async Task<ValidatorInternalResult> Validate(
        AuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        // Step 20
        // If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
        // for that attestation type and attestation statement format fmt, from a trusted source or from policy.
        // For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
        // using the aaguid in the attestedCredentialData in authData.
        if (_configuration.EnableMetadataService)
        {
            var aaGuid = authenticatorData.AttestedCredentialData.AaGuid;
            var authenticatorMetadata = await _metadataService.Get(aaGuid, cancellationToken);
            if (authenticatorMetadata != null)
            {
                if (authenticatorMetadata.HasIncreasedRisk())
                {
                    return ValidatorInternalResult.Invalid(
                        $"Authenticator {aaGuid} has {authenticatorMetadata.GetLastStatus()} status (increased risk)");
                }

                _logger.LogDebug("Authenticator '{AaGuid}' metadata is valid", aaGuid);
            }
            else if (_configuration.EnableStrictAuthenticatorVerification)
            {
                return ValidatorInternalResult.Invalid($"Metadata for authenticator {aaGuid} is not available");
            }
        }

        return ValidatorInternalResult.Valid();
    }

    public async Task<ValidatorInternalResult> ValidateBasicAttestation(
        AuthenticatorData authenticatorData,
        X509Certificate2[]? trustPath,
        CancellationToken cancellationToken)
    {
        // If only basic surrogate attestation is supported by the authenticator, verify that attestation does not
        // contain a full trust path.
        if (_configuration.EnableMetadataService)
        {
            var aaGuid = authenticatorData.AttestedCredentialData.AaGuid;
            var authenticatorMetadata = await _metadataService.Get(aaGuid, cancellationToken);
            if (authenticatorMetadata?.AttestationTypes?.Length == 1 &&
                authenticatorMetadata.AttestationTypes[0] == AttestationType.BasicSurrogate &&
                trustPath?.Length > 0)
            {
                return ValidatorInternalResult.Invalid(
                    $"{AttestationType.BasicSurrogate} (self) attestation type cannot have trust path");
            }
        }

        return ValidatorInternalResult.Valid();
    }
}
