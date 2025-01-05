using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Models.Extensions;
using Shark.Fido2.Models.Requests;

namespace Shark.Fido2.Models.Mappers
{
    public static class PublicKeyCredentialCreationOptionsRequestMapper
    {
        public static PublicKeyCredentialCreationOptionsRequest Map(
            this ServerPublicKeyCredentialCreationOptionsRequest serverRequest)
        {
            var request = new PublicKeyCredentialCreationOptionsRequest
            {
                Username = serverRequest.Username,
                DisplayName = serverRequest.DisplayName,
                AuthenticatorSelection = Map(serverRequest.AuthenticatorSelection),
                Attestation = serverRequest.Attestation,
            };

            return request;
        }

        private static AuthenticatorSelectionCriteria Map(ServerAuthenticatorSelectionCriteriaRequest? criteriaRequest)
        {
            if (criteriaRequest == null)
            {
                return new AuthenticatorSelectionCriteria();
            }

            return new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = criteriaRequest.AuthenticatorAttachment.ToEnum<AuthenticatorAttachment>(),
                ResidentKey = criteriaRequest.ResidentKey.ToEnum<ResidentKeyRequirement>(),
                RequireResidentKey = criteriaRequest.RequireResidentKey,
                UserVerification = criteriaRequest.UserVerification?.ToEnum<UserVerificationRequirement>(),
            };
        }
    }
}
