using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Extensions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialRequestOptionsMapper
{
    /// <summary>
    /// Maps a <see cref="PublicKeyCredentialRequestOptions"/> to a <see cref="ServerPublicKeyCredentialGetOptionsResponse"/>.
    /// </summary>
    /// <param name="requestOptions">The public key credential request options to map.</param>
    /// <returns>A new instance of <see cref="ServerPublicKeyCredentialGetOptionsResponse"/>.</returns>
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

        var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        if (string.Equals(environment, "Test", StringComparison.OrdinalIgnoreCase))
        {
            return new ServerAuthenticationExtensionsClientInputs
            {
                Example = true,
            };
        }

        return new ServerAuthenticationExtensionsClientInputs
        {
            AppId = extensions.AppId,
            UserVerificationMethod = extensions.UserVerificationMethod,
            LargeBlob = extensions.LargeBlob != null ? new ServerAuthenticationExtensionsLargeBlobInputs
            {
                Read = extensions.LargeBlob.Read,
                Write = extensions.LargeBlob.Write,
            }
            : null,
            Example = true,
        };
    }
}
