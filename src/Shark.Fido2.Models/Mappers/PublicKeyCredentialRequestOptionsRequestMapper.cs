using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Requests;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialRequestOptionsRequestMapper
{
    /// <summary>
    /// Maps a <see cref="ServerPublicKeyCredentialGetOptionsRequest"/> to a <see cref="PublicKeyCredentialRequestOptionsRequest"/>.
    /// </summary>
    /// <param name="request">The server public key credential get options request to map.</param>
    /// <returns>A new instance of <see cref="PublicKeyCredentialRequestOptionsRequest"/>.</returns>
    public static PublicKeyCredentialRequestOptionsRequest Map(
        this ServerPublicKeyCredentialGetOptionsRequest request)
    {
        return new PublicKeyCredentialRequestOptionsRequest
        {
            UserName = request.Username,
            UserVerification = request.UserVerification.ToNullableEnum<UserVerificationRequirement>(),
        };
    }
}
