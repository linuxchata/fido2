using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators
{
    public interface IAttestationObjectValidator
    {
        AttestationCompleteResult? Validate();
    }
}
