using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Requests;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialCreationOptionsRequestMapper
{
    public static PublicKeyCredentialCreationOptionsRequest Map(
        this ServerPublicKeyCredentialCreationOptionsRequest request)
    {
        return new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = request.Username,
            DisplayName = request.DisplayName,
            AuthenticatorSelection = Map(request.AuthenticatorSelection),
            Attestation = request.Attestation,
        };
    }

    private static AuthenticatorSelectionCriteria? Map(
        ServerAuthenticatorSelectionCriteriaRequest? authenticatorSelection)
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
