using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Handlers
{
    public interface IClientDataHandler
    {
        InternalResult<ClientData> Handle(string clientDataJson, string expectedChallenge);
    }
}
