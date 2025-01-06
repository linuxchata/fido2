using Shark.Fido2.Domain;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers
{
    public static class PublicKeyCredentialAttestationMapper
    {
        public static PublicKeyCredentialAttestation Map(this ServerPublicKeyCredentialAttestation value)
        {
            return new PublicKeyCredentialAttestation
            {
                Id = value.Id,
                RawId = value.RawId,
                Response = new AuthenticatorAttestationResponse
                {
                    AttestationObject = value.Response.AttestationObject,
                    ClientDataJson = value.Response.ClientDataJson,
                    Signature = value.Response.Signature,
                    UserHandler = value.Response.UserHandler,
                }
            };
        }
    }
}
