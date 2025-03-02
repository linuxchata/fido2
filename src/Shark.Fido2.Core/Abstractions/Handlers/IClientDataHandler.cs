using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Handlers;

public interface IClientDataHandler
{
    InternalResult<ClientData> HandleAttestation(string clientDataJson, string expectedChallenge);

    InternalResult<ClientData> HandleAssertion(string clientDataJson, string expectedChallenge);
}
