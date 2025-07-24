using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Handlers;

public interface IAssertionObjectHandler
{
    InternalResult<AuthenticatorData> Handle(
        string authenticatorDataString,
        string signature,
        ClientData clientData,
        CredentialPublicKey credentialPublicKey,
        AuthenticationExtensionsClientOutputs extensionsClientOutputs,
        PublicKeyCredentialRequestOptions requestOptions);
}
