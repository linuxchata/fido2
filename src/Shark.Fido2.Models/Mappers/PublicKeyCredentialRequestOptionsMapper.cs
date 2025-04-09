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
            ErrorMessage = string.Empty,
            Challenge = requestOptions.Challenge.ToBase64Url(),
            Timeout = requestOptions.Timeout,
            RpId = requestOptions.RpId,
            AllowCredentials = Map(requestOptions.AllowCredentials),
            UserVerification = requestOptions.UserVerification!.Value.GetValue(),
            Extensions = Map(requestOptions.Extensions),
        };

        return response;
    }

    private static ServerPublicKeyCredentialDescriptor[] Map(PublicKeyCredentialDescriptor[]? allowCredentials)
    {
        return allowCredentials?.Select(credential => new ServerPublicKeyCredentialDescriptor
        {
            Type = credential.Type,
            Id = credential.Id.ToBase64Url(),
            Transports = credential.Transports?.Select(t => t.GetValue()).ToArray() ?? [],
        }).ToArray() ?? [];
    }

    private static ServerAuthenticationExtensionsClientInputs? Map(AuthenticationExtensionsClientInputs? extensions)
    {
        if (extensions == null)
        {
            return null;
        }

        return new ServerAuthenticationExtensionsClientInputs
        {
            AppId = extensions.AppId,
            UserVerificationMethod = extensions.UserVerificationMethod,
            LargeBlob = extensions.LargeBlob != null ? new ServerAuthenticationExtensionsLargeBlobInputs
            {
                Support = extensions.LargeBlob.Support,
                Read = extensions.LargeBlob.Read,
                Write = extensions.LargeBlob.Write,
            }
            : null,
            Example = true,
        };
    }
}
