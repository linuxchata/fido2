using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Requests;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialRequestOptionsRequestMapper
{
    public static PublicKeyCredentialRequestOptionsRequest Map(
        this ServerPublicKeyCredentialGetOptionsRequest request)
    {
        return new PublicKeyCredentialRequestOptionsRequest
        {
            Username = request.Username,
            UserVerification = request.UserVerification.ToNullableEnum<UserVerificationRequirement>(),
        };
    }
}
