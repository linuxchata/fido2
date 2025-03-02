using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators;

internal class AssertionResponseValidator : IAssertionObjectValidator
{
    public ValidatorInternalResult Validate(
        AuthenticatorData? authenticatorData,
        ClientData clientData,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        return ValidatorInternalResult.Valid();
    }
}
