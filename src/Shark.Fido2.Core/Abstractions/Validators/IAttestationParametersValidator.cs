using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface IAttestationParametersValidator
{
    void Validate(PublicKeyCredentialCreationOptionsRequest request);

    void Validate(
        PublicKeyCredentialAttestation publicKeyCredentialAttestation,
        PublicKeyCredentialCreationOptions creationOptions);
}
