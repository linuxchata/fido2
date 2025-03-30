using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Tests.Mappers;

[TestFixture]
public class PublicKeyCredentialAssertionMapperTests
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
        var assertion = new ServerPublicKeyCredentialAssertion();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => assertion!.Map());
    }

    [Test]
    public void Map_WhenAssertionValid_ThenReturnsPublicKeyCredentialAssertion()
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
        };

        // Act
        var result = assertion.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Id, Is.EqualTo(assertion.Id));
        Assert.That(result.RawId, Is.EqualTo(assertion.RawId));
        Assert.That(result.Response.ClientDataJson, Is.EqualTo(assertion.Response.ClientDataJson));
        Assert.That(result.Response.AuthenticatorData, Is.EqualTo(assertion.Response.AuthenticatorData));
        Assert.That(result.Response.Signature, Is.EqualTo(assertion.Response.Signature));
        Assert.That(result.Response.UserHandle, Is.EqualTo(assertion.Response.UserHandle));
    }
}