﻿using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions
{
    public interface IAssertion
    {
        PublicKeyCredentialRequestOptions RequestOptions(PublicKeyCredentialRequestOptionsRequest request);
    }
}