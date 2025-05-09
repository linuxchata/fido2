﻿using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface IAssertionObjectValidator
{
    ValidatorInternalResult Validate(
        AuthenticatorData? authenticatorData,
        byte[] authenticatorRawData,
        byte[]? clientDataHash,
        string signature,
        CredentialPublicKey credentialPublicKey,
        AuthenticationExtensionsClientOutputs extensionsClientOutputs,
        PublicKeyCredentialRequestOptions requestOptions);
}
