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
                Transports = Map(attestation.Response.Transports),
            },
            Type = attestation.Type,
            Extensions = Map(attestation.Extensions),
        };
    }

    private static AuthenticatorTransport[] Map(string[]? transports)
    {
        return transports?.Select(t => t.ToEnum<AuthenticatorTransport>()).ToArray() ?? [];
    }

    private static AuthenticationExtensionsClientOutputs Map(ServerAuthenticationExtensionsClientOutputs extensions)
    {
        if (extensions == null || extensions.CredentialProperties == null)
        {
            return new AuthenticationExtensionsClientOutputs();
        }

        return new AuthenticationExtensionsClientOutputs
        {
            CredentialProperties = new CredentialPropertiesOutput
            {
                RequireResidentKey = extensions.CredentialProperties.RequireResidentKey,
            },
        };
    }
}
