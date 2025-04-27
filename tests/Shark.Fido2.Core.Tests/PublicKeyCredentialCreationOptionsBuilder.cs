using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests;

internal static class PublicKeyCredentialCreationOptionsBuilder
{
    internal static PublicKeyCredentialCreationOptions Build()
    {
        return new PublicKeyCredentialCreationOptions
        {
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                RequireResidentKey = false,
                UserVerification = UserVerificationRequirement.Required,
            },
            Challenge = new byte[32],
            ExcludeCredentials = [],
            Extensions = new AuthenticationExtensionsClientInputs(),
            PublicKeyCredentialParams = new List<PublicKeyCredentialParameter>
            {
                new PublicKeyCredentialParameter
                {
                    Type = PublicKeyCredentialType.PublicKey,
                    Algorithm = PublicKeyAlgorithm.Rs256,
                },
            }.ToArray(),
            RelyingParty = new PublicKeyCredentialRpEntity
            {
                Id = "https://localhost:44333",
                Name = "localhost",
            },
            User = new PublicKeyCredentialUserEntity
            {
                DisplayName = "DisplayName",
                Id = new byte[32],
                Name = "Name",
            },
        };
    }
}
