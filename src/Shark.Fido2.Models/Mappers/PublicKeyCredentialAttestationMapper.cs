using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialAttestationMapper
{
    public static PublicKeyCredentialAttestation Map(this ServerPublicKeyCredentialAttestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        ArgumentNullException.ThrowIfNull(attestation.Response);

        return new PublicKeyCredentialAttestation
        {
            Id = attestation.Id,
            RawId = attestation.RawId,
            Response = new AuthenticatorAttestationResponse
            {
                AttestationObject = attestation.Response.AttestationObject,
                ClientDataJson = attestation.Response.ClientDataJson,
                Transports = ConvertTransports(attestation.Response.Transports),
            },
            Type = attestation.Type,
            Extensions = new AuthenticationExtensionsClientOutputs(),
        };
    }

    private static AuthenticatorTransport[] ConvertTransports(string[]? transports)
    {
        return transports?.Select(t => t.ToEnum<AuthenticatorTransport>()).ToArray() ?? [];
    }
}
