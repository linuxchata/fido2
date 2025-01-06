using Shark.Fido2.Domain;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers
{
    public static class PublicKeyCredentialAssertionMapper
    {
        public static PublicKeyCredentialAssertion Map(this ServerPublicKeyCredentialAssertion value)
        {
            return new PublicKeyCredentialAssertion
            {
                Id = value.Id,
                RawId = value.RawId,
                Response = new AuthenticatorAssertionResponse
                {
                    ClientDataJson = value.Response.ClientDataJson,
                    AuthenticatorData = value.Response.AuthenticatorData,
                    Signature = value.Response.Signature,
                    UserHandler = value.Response.UserHandler,
                }
            };
        }
    }
}
