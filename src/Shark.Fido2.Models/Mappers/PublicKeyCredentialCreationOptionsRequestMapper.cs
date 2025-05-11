using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Requests;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialCreationOptionsRequestMapper
{
    public static PublicKeyCredentialCreationOptionsRequest Map(
        this ServerPublicKeyCredentialCreationOptionsRequest serverRequest)
    {
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = serverRequest.Username,
            DisplayName = serverRequest.DisplayName,
            AuthenticatorSelection = Map(serverRequest.AuthenticatorSelection),
            Attestation = serverRequest.Attestation,
        };

        return request;
    }

    private static AuthenticatorSelectionCriteria? Map(ServerAuthenticatorSelectionCriteriaRequest? authenticatorSelection)
    {
        if (authenticatorSelection == null)
        {
            return null;
        }

        return new AuthenticatorSelectionCriteria
        {
            AuthenticatorAttachment = authenticatorSelection.AuthenticatorAttachment?.ToEnum<AuthenticatorAttachment>(),
            ResidentKey = authenticatorSelection.ResidentKey?.ToEnum<ResidentKeyRequirement>() ?? 0,
            RequireResidentKey = authenticatorSelection.RequireResidentKey,
            UserVerification = authenticatorSelection.UserVerification?.ToEnum<UserVerificationRequirement>(),
        };
    }
}
