using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Handlers
{
    public interface IAttestationObjectHandler
    {
        AttestationCompleteResult? Handle(string attestationObject);
    }
}
