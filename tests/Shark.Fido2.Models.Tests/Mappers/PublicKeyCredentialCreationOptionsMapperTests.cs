using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Extensions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Mappers;

namespace Shark.Fido2.Models.Tests.Mappers;

[TestFixture]
internal class PublicKeyCredentialCreationOptionsMapperTests
{
    [Test]
    public void MapCreationOptions_WhenOptionsAreValid_ThenReturnsServerResponse()
    {
        // Arrange
        var challenge = new byte[] { 1, 2, 3, 4 };
        var userId = new byte[] { 10, 20, 30, 40 };
        var excludeId = new byte[] { 50, 60, 70, 80 };
        var creationOptions = new PublicKeyCredentialCreationOptions
        {
            RelyingParty = new PublicKeyCredentialRpEntity
            {
                Id = "example.com",
                Name = "RP Name",
            },
            User = new PublicKeyCredentialUserEntity
            {
                Id = userId,
                Name = "Username",
                DisplayName = "DisplayName",
            },
            Challenge = challenge,
            PublicKeyCredentialParams =
            [
                new PublicKeyCredentialParameter
                {
                    Type = "public-key",
                    Algorithm = CoseAlgorithm.Es256,
                },
            ],
            Timeout = 60000,
            ExcludeCredentials =
            [
                new PublicKeyCredentialDescriptor
                {
                    Type = "public-key",
                    Id = excludeId,
                    Transports = [AuthenticatorTransport.Internal],
                },
            ],
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = AuthenticatorAttachment.Platform,
                ResidentKey = ResidentKeyRequirement.Required,
                RequireResidentKey = true,
                UserVerification = UserVerificationRequirement.Required,
            },
            Attestation = "direct",
            Extensions = new AuthenticationExtensionsClientInputs
            {
                AppIdExclude = "appid-exclude",
                UserVerificationMethod = true,
                CredentialProperties = true,
                LargeBlob = new AuthenticationExtensionsLargeBlobInputs { Support = "supported" },
            },
        };

        // Act
        var result = creationOptions.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("ok"));
        Assert.That(result.ErrorMessage, Is.Empty);
        Assert.That(result.Challenge, Is.EqualTo(challenge.ToBase64Url()));
        Assert.That(result.RelyingParty.Identifier, Is.EqualTo(creationOptions.RelyingParty.Id));
        Assert.That(result.RelyingParty.Name, Is.EqualTo(creationOptions.RelyingParty.Name));
        Assert.That(result.User.Identifier, Is.EqualTo(userId.ToBase64Url()));
        Assert.That(result.User.Name, Is.EqualTo(creationOptions.User.Name));
        Assert.That(result.User.DisplayName, Is.EqualTo(creationOptions.User.DisplayName));
        Assert.That(result.Parameters, Has.Length.EqualTo(1));
        Assert.That(result.Parameters[0].Type, Is.EqualTo("public-key"));
        Assert.That(result.Parameters[0].Algorithm, Is.EqualTo((long)CoseAlgorithm.Es256));
        Assert.That(result.Timeout, Is.EqualTo(creationOptions.Timeout));
        Assert.That(result.ExcludeCredentials, Has.Length.EqualTo(1));
        Assert.That(result.ExcludeCredentials[0].Type, Is.EqualTo("public-key"));
        Assert.That(result.ExcludeCredentials[0].Id, Is.EqualTo(excludeId.ToBase64Url()));
        Assert.That(result.ExcludeCredentials[0].Transports, Has.Length.EqualTo(1));
        Assert.That(result.ExcludeCredentials[0].Transports[0], Is.EqualTo(AuthenticatorTransport.Internal.GetValue()));
        Assert.That(result.AuthenticatorSelection.AuthenticatorAttachment, Is.EqualTo(AuthenticatorAttachment.Platform.GetValue()));
        Assert.That(result.AuthenticatorSelection.ResidentKey, Is.EqualTo(ResidentKeyRequirement.Required.GetValue()));
        Assert.That(result.AuthenticatorSelection.RequireResidentKey, Is.True);
        Assert.That(result.AuthenticatorSelection.UserVerification, Is.EqualTo(UserVerificationRequirement.Required.GetValue()));
        Assert.That(result.Attestation, Is.EqualTo(creationOptions.Attestation));
        Assert.That(result.Extensions, Is.Not.Null);
        Assert.That(result.Extensions.AppIdExclude, Is.EqualTo(creationOptions.Extensions.AppIdExclude));
        Assert.That(result.Extensions.UserVerificationMethod, Is.EqualTo(creationOptions.Extensions.UserVerificationMethod));
        Assert.That(result.Extensions.CredentialProperties, Is.EqualTo(creationOptions.Extensions.CredentialProperties));
        Assert.That(result.Extensions.LargeBlob, Is.Not.Null);
        Assert.That(result.Extensions.LargeBlob.Support, Is.EqualTo(creationOptions.Extensions.LargeBlob!.Support));
        Assert.That(result.Extensions.Example, Is.True);
    }

    [Test]
    public void MapCreationOptions_WhenExtensionsIsNull_ThenReturnsServerResponseWithNullExtensions()
    {
        // Arrange
        var creationOptions = new PublicKeyCredentialCreationOptions
        {
            RelyingParty = new PublicKeyCredentialRpEntity
            {
                Id = "example.com",
                Name = "RP Name",
            },
            User = new PublicKeyCredentialUserEntity
            {
                Id = [1],
                Name = "Username",
                DisplayName = "DisplayName",
            },
            Challenge = [1],
            PublicKeyCredentialParams =
            [
                new PublicKeyCredentialParameter
                {
                    Type = "public-key",
                    Algorithm = CoseAlgorithm.Es256,
                },
            ],
            Timeout = 1000,
            ExcludeCredentials = [],
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = null,
                ResidentKey = ResidentKeyRequirement.Discouraged,
                RequireResidentKey = false,
                UserVerification = UserVerificationRequirement.Preferred,
            },
            Attestation = "none",
            Extensions = null!,
        };

        // Act
        var result = creationOptions.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Extensions, Is.Null);
    }

    [Test]
    public void MapCreationOptions_WhenAuthenticatorSelectionIsNull_ThenReturnsServerResponseWithPreferredUserVerification()
    {
        // Arrange
        var creationOptions = new PublicKeyCredentialCreationOptions
        {
            RelyingParty = new PublicKeyCredentialRpEntity
            {
                Id = "example.com",
                Name = "RP Name",
            },
            User = new PublicKeyCredentialUserEntity
            {
                Id = [1],
                Name = "Username",
                DisplayName = "DisplayName",
            },
            Challenge = [1],
            PublicKeyCredentialParams = [
                new PublicKeyCredentialParameter
                {
                    Type = "public-key",
                    Algorithm = CoseAlgorithm.Es256,
                },
            ],
            Timeout = 1000,
            ExcludeCredentials = [],
            AuthenticatorSelection = null!,
            Attestation = "none",
            Extensions = null!,
        };

        // Act
        var result = creationOptions.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AuthenticatorSelection.UserVerification, Is.EqualTo(UserVerificationRequirement.Preferred.ToString()));
    }
}
