using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators
{
    public interface IAttestationStatementStategy
    {
        ValidatorInternalResult Validate(
            object? attestationStatement,
            AuthenticatorData authenticatorData,
            PublicKeyCredentialCreationOptions creationOptions);
    }
}
