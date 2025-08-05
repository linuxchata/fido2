using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate client data.
/// </summary>
public interface IClientDataValidator
{
    /// <summary>
    /// Validates the client data for the attestation.
    /// </summary>
    /// <param name="clientData">The client data.</param>
    /// <param name="expectedChallenge">The challenge.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateForAttestation(ClientData clientData, string expectedChallenge);

    /// <summary>
    /// Validates the client data for the assertion.
    /// </summary>
    /// <param name="clientData">The client data.</param>
    /// <param name="expectedChallenge">The challenge.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult ValidateForAssertion(ClientData clientData, string expectedChallenge);
}
