using Shark.Fido2.Core.Results;
using Shark.Fido2.Metadata.Core.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// Validates the trustworthiness of an attestation statement.
/// </summary>
public interface IAttestationTrustworthinessValidator
{
    /// <summary>
    /// Validates the attestation statement trustworthiness.
    /// </summary>
    /// <param name="attestationStatementResult">The result from attestation statement validation.</param>
    /// <param name="metadataPayloadItem">The authenticator metadata.</param>
    /// <returns>A ValidatorInternalResult indicating whether the attestation is trustworthy.</returns>
    ValidatorInternalResult Validate(
        AttestationStatementInternalResult attestationStatementResult,
        MetadataPayloadItem? metadataPayloadItem);
}
