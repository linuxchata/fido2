using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate attestation againts acceptable trust anchors.
/// </summary>
public interface IAttestationTrustAnchorValidator
{
    /// <summary>
    /// Validates attestation againts acceptable trust anchors.
    /// </summary>
    /// <param name="authenticatorData">The authenticator data.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    Task<ValidatorInternalResult> Validate(AuthenticatorData authenticatorData);

    /// <summary>
    /// Validates basic attestation againts acceptable trust anchors.
    /// </summary>
    /// <param name="authenticatorData">The authenticator data.</param>
    /// <param name="trustPath">The trust path (the list of X509 certificates).</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    Task<ValidatorInternalResult> ValidateBasicAttestation(
        AuthenticatorData authenticatorData,
        X509Certificate2[]? trustPath);
}
