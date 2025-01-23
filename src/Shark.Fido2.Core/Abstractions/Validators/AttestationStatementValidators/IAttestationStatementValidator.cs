using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

public interface IAttestationStatementValidator
{
    void Validate(
        AttestationObjectData attestationObjectData,
        AuthenticatorData authenticatorData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions);
}
