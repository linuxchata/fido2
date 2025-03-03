using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface IAssertionObjectValidator
{
    ValidatorInternalResult Validate(
        byte[] authenticatorRawData,
        AuthenticatorData? authenticatorData,
        string signature,
        ClientData clientData,
        CredentialPublicKey credentialPublicKey,
        PublicKeyCredentialRequestOptions requestOptions);
}
