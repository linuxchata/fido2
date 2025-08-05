using Shark.Fido2.Core.Results;
using Shark.Fido2.Metadata.Core.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate attestation trustworthiness.
/// </summary>
public interface IAttestationTrustworthinessValidator
{
    /// <summary>
    /// Validates the attestation statement trustworthiness.
    /// </summary>
    /// <param name="attestationStatementResult">The result from attestation statement validation.</param>
    /// <param name="metadataPayloadItem">The authenticator metadata.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(
        AttestationStatementInternalResult attestationStatementResult,
        MetadataPayloadItem? metadataPayloadItem);
}
