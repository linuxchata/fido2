﻿using System;
using System.Linq;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers
{
    public static class PublicKeyCredentialCreationOptionsMapper
    {
        public static ServerPublicKeyCredentialCreationOptionsResponse Map(
            this PublicKeyCredentialCreationOptions credentialOptions)
        {
            var response = new ServerPublicKeyCredentialCreationOptionsResponse
            {
                Status = "ok",
                Challenge = Convert.ToBase64String(credentialOptions.Challenge),
                RelyingParty = new RelyingPartyResponse
                {
                    Identifier = credentialOptions.RelyingParty.Id,
                    Name = credentialOptions.RelyingParty.Name,
                },
                User = new UserResponse
                {
                    Identifier = Guid.NewGuid().ToString(),
                    Name = "johndoe@example.com",
                    DisplayName = "John Doe",
                },
                Parameters = credentialOptions.PublicKeyCredentialParams?.Select(p => new ParameterResponse
                {
                    Type = p.Type,
                    Algorithm = (long)p.Algorithm,
                }).ToArray() ?? new ParameterResponse[0],
                Timeout = credentialOptions.Timeout,
            };

            return response;
        }
    }
}
