using Shark.Fido2.Domain;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialAssertionMapper
{
    public static PublicKeyCredentialAssertion Map(this ServerPublicKeyCredentialAssertion assertion)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(assertion.Response);

        return new PublicKeyCredentialAssertion
        {
            Id = assertion.Id,
            RawId = assertion.RawId,
            Response = new AuthenticatorAssertionResponse
            {
                ClientDataJson = assertion.Response.ClientDataJson,
                AuthenticatorData = assertion.Response.AuthenticatorData,
                Signature = assertion.Response.Signature!,
                UserHandle = assertion.Response.UserHandle,
            },
            Type = assertion.Type,
            Extensions = Map(assertion.Extensions),
        };
    }

    private static AuthenticationExtensionsClientOutputs Map(ServerAuthenticationExtensionsClientOutputs? extensions)
    {
        if (extensions == null)
        {
            return new AuthenticationExtensionsClientOutputs();
        }

        return new AuthenticationExtensionsClientOutputs
        {
            AppId = extensions.AppId,
            UserVerificationMethod = extensions.UserVerificationMethod,
            LargeBlob = extensions.LargeBlob != null ? new AuthenticationExtensionsLargeBlobOutputs
            {
                Blob = extensions.LargeBlob.Blob,
                Written = extensions.LargeBlob.Written,
            }
            : null,
        };
    }
}
