using Shark.Fido2.Core.Models;
using Shark.Fido2.Core.Results.Attestation;

namespace Shark.Fido2.Core.Abstractions.Handlers
{
    public interface IClientDataHandler
    {
        InternalResult<ClientDataModel> Handle(string clientDataJson, string expectedChallenge);
    }
}
