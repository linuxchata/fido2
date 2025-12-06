using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Tests.Mappers;

[TestFixture]
internal class PublicKeyCredentialAssertionMapperTests
{
    [Test]
    public void Map_WhenAssertionIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var assertion = (ServerPublicKeyCredentialAssertion)null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => assertion!.Map());
    }

    [Test]
    public void Map_WhenAssertionResponseIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var assertion = new ServerPublicKeyCredentialAssertion
        {
            Id = "Id",
            RawId = "RawId",
            Response = null!,
            Type = PublicKeyCredentialType.PublicKey,
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => assertion.Map());
    }

    [Test]
    public void Map_WhenAssertionIsValid_ThenReturnsPublicKeyCredentialAssertion()
    {
        // Arrange
        var assertion = new ServerPublicKeyCredentialAssertion
        {
            Id = "Id",
            RawId = "RawId",
            Response = new ServerAuthenticatorAssertionResponse
            {
                ClientDataJson = "ClientDataJson",
                AuthenticatorData = "AuthenticatorData",
                Signature = "Signature",
                UserHandle = "UserHandler",
            },
            Type = PublicKeyCredentialType.PublicKey,
        };

        // Act
        var result = assertion.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Id, Is.EqualTo(assertion.Id));
        Assert.That(result.RawId, Is.EqualTo(assertion.RawId));
        Assert.That(result.Type, Is.EqualTo(assertion.Type));
        Assert.That(result.Response.ClientDataJson, Is.EqualTo(assertion.Response.ClientDataJson));
        Assert.That(result.Response.AuthenticatorData, Is.EqualTo(assertion.Response.AuthenticatorData));
        Assert.That(result.Response.Signature, Is.EqualTo(assertion.Response.Signature));
        Assert.That(result.Response.UserHandle, Is.EqualTo(assertion.Response.UserHandle));
        Assert.That(result.Extensions, Is.Not.Null);
    }

    [Test]
    public void Map_WhenAssertionIsValidAndWithAppIdUserVerificationMethodLargeBlobExtensions_ThenReturnsPublicKeyCredentialAssertion()
    {
        // Arrange
        var assertion = new ServerPublicKeyCredentialAssertion
        {
            Id = "Id",
            RawId = "RawId",
            Response = new ServerAuthenticatorAssertionResponse
            {
                ClientDataJson = "ClientDataJson",
                AuthenticatorData = "AuthenticatorData",
                Signature = "Signature",
                UserHandle = "UserHandler",
            },
            Type = PublicKeyCredentialType.PublicKey,
            Extensions = new ServerAuthenticationExtensionsClientOutputs
            {
                AppId = true,
                UserVerificationMethod = [[1236]],
                LargeBlob = new ServerAuthenticationExtensionsLargeBlobOutputs
                {
                    Blob = "blob-data",
                    Written = true,
                },
            },
        };

        // Act
        var result = assertion.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Id, Is.EqualTo(assertion.Id));
        Assert.That(result.RawId, Is.EqualTo(assertion.RawId));
        Assert.That(result.Type, Is.EqualTo(assertion.Type));
        Assert.That(result.Response.ClientDataJson, Is.EqualTo(assertion.Response.ClientDataJson));
        Assert.That(result.Response.AuthenticatorData, Is.EqualTo(assertion.Response.AuthenticatorData));
        Assert.That(result.Response.Signature, Is.EqualTo(assertion.Response.Signature));
        Assert.That(result.Response.UserHandle, Is.EqualTo(assertion.Response.UserHandle));
        Assert.That(result.Extensions, Is.Not.Null);
        Assert.That(result.Extensions.AppId, Is.EqualTo(assertion.Extensions.AppId));
        Assert.That(result.Extensions.UserVerificationMethod, Is.EqualTo(assertion.Extensions.UserVerificationMethod));
        Assert.That(result.Extensions.LargeBlob, Is.Not.Null);
        Assert.That(result.Extensions.LargeBlob!.Blob, Is.EqualTo(assertion.Extensions.LargeBlob.Blob));
        Assert.That(result.Extensions.LargeBlob.Written, Is.EqualTo(assertion.Extensions.LargeBlob.Written));
    }

    [Test]
    public void Map_WhenAssertionIsValidAndWithAppIdUserVerificationMethodExtensions_ThenReturnsPublicKeyCredentialAssertion()
    {
        // Arrange
        var assertion = new ServerPublicKeyCredentialAssertion
        {
            Id = "Id",
            RawId = "RawId",
            Response = new ServerAuthenticatorAssertionResponse
            {
                ClientDataJson = "ClientDataJson",
                AuthenticatorData = "AuthenticatorData",
                Signature = "Signature",
                UserHandle = "UserHandler",
            },
            Type = PublicKeyCredentialType.PublicKey,
            Extensions = new ServerAuthenticationExtensionsClientOutputs
            {
                AppId = true,
                UserVerificationMethod = [[1236]],
                LargeBlob = null!,
            },
        };

        // Act
        var result = assertion.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Id, Is.EqualTo(assertion.Id));
        Assert.That(result.RawId, Is.EqualTo(assertion.RawId));
        Assert.That(result.Type, Is.EqualTo(assertion.Type));
        Assert.That(result.Response.ClientDataJson, Is.EqualTo(assertion.Response.ClientDataJson));
        Assert.That(result.Response.AuthenticatorData, Is.EqualTo(assertion.Response.AuthenticatorData));
        Assert.That(result.Response.Signature, Is.EqualTo(assertion.Response.Signature));
        Assert.That(result.Response.UserHandle, Is.EqualTo(assertion.Response.UserHandle));
        Assert.That(result.Extensions, Is.Not.Null);
        Assert.That(result.Extensions.AppId, Is.EqualTo(assertion.Extensions.AppId));
        Assert.That(result.Extensions.UserVerificationMethod, Is.EqualTo(assertion.Extensions.UserVerificationMethod));
        Assert.That(result.Extensions.LargeBlob, Is.Null);
    }
}