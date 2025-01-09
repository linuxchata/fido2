using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators
{
    public interface IAttestationObjectValidator
    {
        ValidatorInternalResult Validate(
            AttestationObjectData? attestationObjectData,
            PublicKeyCredentialCreationOptions creationOptions);
    }
}
