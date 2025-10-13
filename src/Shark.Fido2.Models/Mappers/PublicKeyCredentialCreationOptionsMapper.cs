using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Extensions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Mappers;

public static class PublicKeyCredentialCreationOptionsMapper
{
    public static ServerPublicKeyCredentialCreationOptionsResponse Map(
        this PublicKeyCredentialCreationOptions credentialOptions)
    {
        var response = new ServerPublicKeyCredentialCreationOptionsResponse
        {
            Status = "ok",
            ErrorMessage = string.Empty,
            Challenge = credentialOptions.Challenge.ToBase64Url(),
            RelyingParty = Map(credentialOptions.RelyingParty),
            User = Map(credentialOptions.User),
            Parameters = Map(credentialOptions.PublicKeyCredentialParams),
            Timeout = credentialOptions.Timeout,
            ExcludeCredentials = Map(credentialOptions.ExcludeCredentials),
            AuthenticatorSelection = Map(credentialOptions.AuthenticatorSelection),
            Attestation = credentialOptions.Attestation,
            Extensions = Map(credentialOptions.Extensions),
        };

        return response;
    }

    private static ServerPublicKeyCredentialRpEntity Map(PublicKeyCredentialRpEntity rpEntity)
    {
        return new ServerPublicKeyCredentialRpEntity
        {
            Identifier = rpEntity.Id,
            Name = rpEntity.Name,
        };
    }

    private static ServerPublicKeyCredentialUserEntity Map(PublicKeyCredentialUserEntity userEntity)
    {
        return new ServerPublicKeyCredentialUserEntity
        {
            Identifier = userEntity.Id.ToBase64Url(),
            Name = userEntity.Name,
            DisplayName = userEntity.DisplayName,
        };
    }

    private static ServerPublicKeyCredentialParameters[] Map(PublicKeyCredentialParameter[] parameters)
    {
        return parameters?.Select(p => new ServerPublicKeyCredentialParameters
        {
            Type = p.Type,
            Algorithm = (long)p.Algorithm,
        }).ToArray() ?? [];
    }

    private static ServerPublicKeyCredentialDescriptor[] Map(PublicKeyCredentialDescriptor[]? excludeCredentials)
    {
        return excludeCredentials?.Select(credential => new ServerPublicKeyCredentialDescriptor
        {
            Type = credential.Type,
            Id = credential.Id.ToBase64Url(),
            Transports = credential.Transports?.Select(t => t.GetValue()).ToArray() ?? [],
        }).ToArray() ?? [];
    }

    private static ServerAuthenticatorSelectionCriteria Map(AuthenticatorSelectionCriteria authenticatorSelection)
    {
        if (authenticatorSelection == null)
        {
            return new ServerAuthenticatorSelectionCriteria
            {
                UserVerification = $"{UserVerificationRequirement.Preferred}",
            };
        }

        return new ServerAuthenticatorSelectionCriteria
        {
            AuthenticatorAttachment = authenticatorSelection.AuthenticatorAttachment?.GetValue(),
            ResidentKey = authenticatorSelection.ResidentKey != 0 ? authenticatorSelection.ResidentKey.GetValue() : null,
            RequireResidentKey = authenticatorSelection.RequireResidentKey,
            UserVerification = authenticatorSelection.UserVerification!.Value.GetValue(),
        };
    }

    private static ServerAuthenticationExtensionsClientInputs? Map(AuthenticationExtensionsClientInputs extensions)
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
            AppIdExclude = extensions.AppIdExclude,
            UserVerificationMethod = extensions.UserVerificationMethod,
            CredentialProperties = extensions.CredentialProperties,
            LargeBlob = extensions.LargeBlob != null ? new ServerAuthenticationExtensionsLargeBlobInputs
            {
                Support = extensions.LargeBlob.Support,
            }
             : null,
            Example = true,
        };
    }
}
