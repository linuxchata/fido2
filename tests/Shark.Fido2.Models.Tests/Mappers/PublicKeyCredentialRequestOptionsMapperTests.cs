using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Mappers;

namespace Shark.Fido2.Models.Tests.Mappers;

[TestFixture]
public class PublicKeyCredentialRequestOptionsMapperTests
{
    [Test]
    public void MapRequestOptions_WhenOptionsAreValid_ThenReturnsServerResponse()
    {
        // Arrange
        var challenge = new byte[] { 1, 2, 3, 4 };
        var credentialId = new byte[] { 5, 6, 7, 8 };
        var options = new PublicKeyCredentialRequestOptions
        {
            Challenge = challenge,
            Timeout = 60000,
            RpId = "example.com",
            AllowCredentials =
            [
                new PublicKeyCredentialDescriptor
                {
                    Type = "public-key",
                    Id = credentialId,
                    Transports = [AuthenticatorTransport.Internal,],
                },
            ],
            UserVerification = UserVerificationRequirement.Required,
            Extensions = new AuthenticationExtensionsClientInputs
            {
                AppId = "https://example.com",
                UserVerificationMethod = true,
                LargeBlob = new AuthenticationExtensionsLargeBlobInputs
                {
                    Read = true,
                    Write = null,
                },
            },
        };

        // Act
        var result = options.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("ok"));
        Assert.That(result.ErrorMessage, Is.Empty);
        Assert.That(result.Challenge, Is.EqualTo(challenge.ToBase64Url()));
        Assert.That(result.Timeout, Is.EqualTo(options.Timeout));
        Assert.That(result.RpId, Is.EqualTo(options.RpId));
        Assert.That(result.UserVerification, Is.EqualTo(UserVerificationRequirement.Required.GetValue()));

        Assert.That(result.AllowCredentials, Has.Length.EqualTo(1));
        var credential = result.AllowCredentials[0];
        Assert.That(credential.Type, Is.EqualTo("public-key"));
        Assert.That(credential.Id, Is.EqualTo(credentialId.ToBase64Url()));
        Assert.That(credential.Transports, Has.Length.EqualTo(1));
        Assert.That(credential.Transports[0], Is.EqualTo(AuthenticatorTransport.Internal.GetValue()));

        Assert.That(result.Extensions, Is.Not.Null);
        Assert.That(result.Extensions.AppId, Is.EqualTo(options.Extensions.AppId));
        Assert.That(result.Extensions.UserVerificationMethod, Is.EqualTo(options.Extensions.UserVerificationMethod));
        Assert.That(result.Extensions.Example, Is.True);
        Assert.That(result.Extensions.LargeBlob, Is.Not.Null);
        Assert.That(result.Extensions.LargeBlob.Read, Is.True);
        Assert.That(result.Extensions.LargeBlob.Write, Is.Null);
    }

    [Test]
    public void MapRequestOptions_WhenAllowCredentialsIsNull_ThenReturnsServerResponseWithEmptyAllowCredentials()
    {
        // Arrange
        var challenge = new byte[] { 1, 2, 3, 4 };
        var options = new PublicKeyCredentialRequestOptions
        {
            Challenge = challenge,
            Timeout = 60000,
            RpId = "example.com",
            AllowCredentials = null,
            UserVerification = UserVerificationRequirement.Required,
            Extensions = null,
        };

        // Act
        var result = options.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AllowCredentials, Is.Empty);
    }

    [Test]
    public void MapRequestOptions_WhenExtensionsAreNull_ThenReturnsServerResponseWithNullExtensions()
    {
        // Arrange
        var challenge = new byte[] { 1, 2, 3, 4 };
        var options = new PublicKeyCredentialRequestOptions
        {
            Challenge = challenge,
            Timeout = 60000,
            RpId = "example.com",
            AllowCredentials = [],
            UserVerification = UserVerificationRequirement.Required,
            Extensions = null,
        };

        // Act
        var result = options.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Extensions, Is.Null);
    }
}