﻿using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Handlers;

public interface IAssertionObjectHandler
{
    InternalResult<AuthenticatorData> Handle(
        string authenticatorData,
        ClientData clientData,
        PublicKeyCredentialRequestOptions requestOptions);
}
