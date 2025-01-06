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
                RelyingParty = Map(credentialOptions.RelyingParty),
                User = Map(credentialOptions.User),
                Parameters = Map(credentialOptions.PublicKeyCredentialParams),
                Timeout = credentialOptions.Timeout,
                ExcludeCredentials = Map(credentialOptions.ExcludeCredentials),
                AuthenticatorSelection = Map(credentialOptions.AuthenticatorSelection),
                Attestation = credentialOptions.Attestation,
            };

            return response;
        }

        private static ServerPublicKeyCredentialRpEntity Map(PublicKeyCredentialRpEntity relyingParty)
        {
            return new ServerPublicKeyCredentialRpEntity
            {
                Identifier = relyingParty.Id,
                Name = relyingParty.Name,
            };
        }

        private static ServerPublicKeyCredentialUserEntity Map(PublicKeyCredentialUserEntity userEntity)
        {
            if (userEntity == null)
            {
                return new ServerPublicKeyCredentialUserEntity();
            }

            return new ServerPublicKeyCredentialUserEntity
            {
                Identifier = Convert.ToBase64String(userEntity.Id),
                Name = userEntity.Name,
                DisplayName = userEntity.DisplayName,
            };
        }

        private static ServerPublicKeyCredentialParameters[] Map(PublicKeyCredentialParameter[] publicKeyCredentialParams)
        {
            return publicKeyCredentialParams?.Select(p => new ServerPublicKeyCredentialParameters
            {
                Type = p.Type,
                Algorithm = (long)p.Algorithm,
            }).ToArray() ?? new ServerPublicKeyCredentialParameters[0];
        }

        private static ServerPublicKeyCredentialDescriptor[] Map(PublicKeyCredentialDescriptor[]? excludeCredentials)
        {
            return excludeCredentials?.Select(credential => new ServerPublicKeyCredentialDescriptor
            {
                Type = credential.Type,
                Id = Convert.ToBase64String(credential.Id),
                Transports = credential.Transports.Select(t => t.GetValue()).ToArray(),
            }).ToArray() ?? new ServerPublicKeyCredentialDescriptor[0];
        }

        private static Responses.ServerAuthenticatorSelectionCriteria Map(Domain.AuthenticatorSelectionCriteria authenticatorSelection)
        {
            if (authenticatorSelection == null)
            {
                return new Responses.ServerAuthenticatorSelectionCriteria();
            }

            return new Responses.ServerAuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = authenticatorSelection.AuthenticatorAttachment.GetValue(),
                ResidentKey = authenticatorSelection.ResidentKey.GetValue(),
                RequireResidentKey = authenticatorSelection.RequireResidentKey,
                UserVerification = authenticatorSelection.UserVerification!.Value.GetValue(),
            };
        }
    }
}
