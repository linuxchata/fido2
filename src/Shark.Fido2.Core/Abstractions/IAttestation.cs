﻿using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions;

public interface IAttestation
{
    Task<PublicKeyCredentialCreationOptions> GetOptions(PublicKeyCredentialCreationOptionsRequest request);

    Task<AttestationCompleteResult> Complete(
        PublicKeyCredentialAttestation publicKeyCredential,
        PublicKeyCredentialCreationOptions creationOptions);
}
