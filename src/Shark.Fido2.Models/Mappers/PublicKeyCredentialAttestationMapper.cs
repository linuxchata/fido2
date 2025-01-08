using System;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers
{
    public static class PublicKeyCredentialAttestationMapper
    {
        public static PublicKeyCredentialAttestation Map(this ServerPublicKeyCredentialAttestation attestation)
        {
            if (attestation == null)
            {
                throw new ArgumentNullException(nameof(attestation));
            }

            if (attestation.Response == null)
            {
                throw new ArgumentNullException(nameof(attestation.Response));
            }

            return new PublicKeyCredentialAttestation
            {
                Id = attestation.Id,
                RawId = attestation.RawId,
                Response = new AuthenticatorAttestationResponse
                {
                    AttestationObject = attestation.Response.AttestationObject,
                    ClientDataJson = attestation.Response.ClientDataJson,
                    Signature = attestation.Response.Signature,
                    UserHandler = attestation.Response.UserHandler,
                }
            };
        }
    }
}
