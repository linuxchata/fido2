using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators
{
    public interface IAttestationStatementValidator
    {
        void Validate(
            string attestationStatementFormat,
            object? attestationStatement,
            AuthenticatorData authenticatorData,
            PublicKeyCredentialCreationOptions creationOptions);
    }
}
