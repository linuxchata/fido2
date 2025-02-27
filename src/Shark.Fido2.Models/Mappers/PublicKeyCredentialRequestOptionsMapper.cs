using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialRequestOptionsMapper
{
    public static ServerPublicKeyCredentialGetOptionsResponse Map(
        this PublicKeyCredentialRequestOptions requestOptions)
    {
        var response = new ServerPublicKeyCredentialGetOptionsResponse
        {
            Status = "ok",
            Challenge = Convert.ToBase64String(requestOptions.Challenge),
            Timeout = requestOptions.Timeout,
            RpId = requestOptions.RpId,
            AllowCredentials = Map(requestOptions.AllowCredentials),
            UserVerification = requestOptions.UserVerification!.Value.GetValue(),
        };

        return response;
    }

    private static ServerPublicKeyCredentialDescriptor[] Map(PublicKeyCredentialDescriptor[]? allowCredentials)
    {
        return allowCredentials?.Select(credential => new ServerPublicKeyCredentialDescriptor
        {
            Type = credential.Type,
            Id = Convert.ToBase64String(credential.Id),
            Transports = credential.Transports?.Select(t => t.GetValue()).ToArray() ?? [],
        }).ToArray() ?? [];
    }
}
