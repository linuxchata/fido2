using System;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers
{
    public static class PublicKeyCredentialAssertionMapper
    {
        public static PublicKeyCredentialAssertion Map(this ServerPublicKeyCredentialAssertion assertion)
        {
            if (assertion == null)
            {
                throw new ArgumentNullException(nameof(assertion));
            }

            if (assertion.Response == null)
            {
                throw new ArgumentNullException(nameof(assertion.Response));
            }

            return new PublicKeyCredentialAssertion
            {
                Id = assertion.Id,
                RawId = assertion.RawId,
                Response = new AuthenticatorAssertionResponse
                {
                    ClientDataJson = assertion.Response.ClientDataJson,
                    AuthenticatorData = assertion.Response.AuthenticatorData,
                    Signature = assertion.Response.Signature!,
                    UserHandler = assertion.Response.UserHandler,
                }
            };
        }
    }
}
