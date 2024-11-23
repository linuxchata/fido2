using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Handlers
{
    public interface IClientDataHandler
    {
        AttestationCompleteResult? Handle(string clientDataJson, string expectedChallenge);
    }
}
