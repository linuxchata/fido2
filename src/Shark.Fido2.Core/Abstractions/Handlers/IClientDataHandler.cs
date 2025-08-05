using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Handlers;

/// <summary>
/// The interface representing the logic to handle client data.
/// </summary>
public interface IClientDataHandler
{
    /// <summary>
    /// Handles the processing of client data from an attestation (registration) response.
    /// </summary>
    /// <param name="clientDataJson">The JSON string containing the client data from the attestation.</param>
    /// <param name="expectedChallenge">The challenge.</param>
    /// <returns>The result of processing the client data, containing the parsed client data or validation errors.</returns>
    InternalResult<ClientData> HandleAttestation(string clientDataJson, string expectedChallenge);

    /// <summary>
    /// Handles the processing of client data from an assertion (authentication) response.
    /// </summary>
    /// <param name="clientDataJson">The JSON string containing the client data from the assertion.</param>
    /// <param name="expectedChallenge">The challenge.</param>
    /// <returns>The result of processing the client data, containing the parsed client data or validation errors.</returns>
    InternalResult<ClientData> HandleAssertion(string clientDataJson, string expectedChallenge);
}
