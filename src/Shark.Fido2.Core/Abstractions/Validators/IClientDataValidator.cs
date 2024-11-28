using Shark.Fido2.Core.Models;
using Shark.Fido2.Core.Results;

namespace Shark.Fido2.Core.Abstractions.Validators
{
    public interface IClientDataValidator
    {
        ValidatorInternalResult Validate(ClientDataModel? clientData, string expectedChallenge);
    }
}
