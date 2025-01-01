using System;
using System.Linq;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Extensions;
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
                Parameters = Map(credentialOptions.PublicKeyCredentialParams),
                Timeout = credentialOptions.Timeout,
                ExcludeCredentials = Map(credentialOptions.ExcludeCredentials),
                AuthenticatorSelection = Map(credentialOptions.AuthenticatorSelection),
                Attestation = credentialOptions.Attestation,
            };

            return response;
        }

        private static ParameterResponse[] Map(PublicKeyCredentialParameter[] publicKeyCredentialParams)
        {
            return publicKeyCredentialParams?.Select(p => new ParameterResponse
            {
                Type = p.Type,
                Algorithm = (long)p.Algorithm,
            }).ToArray() ?? new ParameterResponse[0];
        }

        private static DescriptorResponse[] Map(PublicKeyCredentialDescriptor[]? excludeCredentials)
        {
            return excludeCredentials?.Select(credentials => new DescriptorResponse
            {
                Type = credentials.Type,
                Id = Convert.ToBase64String(credentials.Id),
                Transports = credentials.Transports.Select(t => t.GetEnumMemberValue()).ToArray(),
            }).ToArray() ?? new DescriptorResponse[0];
        }

        private static AuthenticatorSelectionCriteriaResponse Map(AuthenticatorSelectionCriteria authenticatorSelection)
        {
            if (authenticatorSelection == null)
            {
                return new AuthenticatorSelectionCriteriaResponse();
            }

            return new AuthenticatorSelectionCriteriaResponse
            {
                AuthenticatorAttachment = authenticatorSelection.AuthenticatorAttachment,
                ResidentKey = authenticatorSelection.ResidentKey,
                RequireResidentKey = authenticatorSelection.RequireResidentKey,
                UserVerification = authenticatorSelection.UserVerification,
            };
        }
    }
}
