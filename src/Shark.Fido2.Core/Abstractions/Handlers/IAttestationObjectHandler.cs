using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Handlers;

public interface IAttestationObjectHandler
{
    Task<InternalResult<AttestationObjectData>> Handle(
        string attestationObject,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions);
}
