using Shark.Fido2.Core.Results;

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
    /// <returns>A ValidatorInternalResult indicating whether the attestation is trustworthy.</returns>
    ValidatorInternalResult Validate(AttestationStatementInternalResult attestationStatementResult);
}
