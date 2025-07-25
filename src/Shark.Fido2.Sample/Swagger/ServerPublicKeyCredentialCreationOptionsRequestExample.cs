﻿using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Models.Requests;
using Swashbuckle.AspNetCore.Filters;

namespace Shark.Fido2.Sample.Swagger;

public class ServerPublicKeyCredentialCreationOptionsRequestExample :
    IExamplesProvider<ServerPublicKeyCredentialCreationOptionsRequest>
{
    public ServerPublicKeyCredentialCreationOptionsRequest GetExamples()
    {
        return new ServerPublicKeyCredentialCreationOptionsRequest
        {
            Username = "shark",
            DisplayName = "shark",
            AuthenticatorSelection = new ServerAuthenticatorSelectionCriteriaRequest
            {
                AuthenticatorAttachment = "platform",
                ResidentKey = "required",
                RequireResidentKey = false,
                UserVerification = "required",
            },
            Attestation = AttestationConveyancePreference.Direct,
        };
    }
}
