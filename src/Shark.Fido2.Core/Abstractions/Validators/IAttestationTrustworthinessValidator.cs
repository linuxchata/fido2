using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate attestation trustworthiness.
/// </summary>
public interface IAttestationTrustworthinessValidator
{
    /// <summary>
    /// Validates the attestation statement trustworthiness.
    /// </summary>
    /// <param name="authenticatorData">The authenticator data.</param>
    /// <param name="attestationStatementResult">The result from attestation statement validation.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    Task<ValidatorInternalResult> Validate(
        AuthenticatorData authenticatorData,
        AttestationStatementInternalResult attestationStatementResult);
}
