using Shark.Fido2.Core.Models;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators
{
    public interface IClientDataValidator
    {
        AttestationCompleteResult? Validate(ClientDataModel? clientData, string expectedChallenge);
    }
}
