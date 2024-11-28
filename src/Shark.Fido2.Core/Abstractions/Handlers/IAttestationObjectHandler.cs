using Shark.Fido2.Core.Models;
using Shark.Fido2.Core.Results.Attestation;

namespace Shark.Fido2.Core.Abstractions.Handlers
{
    public interface IAttestationObjectHandler
    {
        InternalResult<AttestationObjectDataModel> Handle(string attestationObject);
    }
}
