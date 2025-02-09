using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Tests.Mappers;

[TestFixture]
public class PublicKeyCredentialAttestationMapperTests
{
    [Test]
    public void Map_WhenAttestationIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var attestation = (ServerPublicKeyCredentialAttestation)null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => attestation!.Map());
    }

    [Test]
    public void Map_WhenAttestationResponseIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var attestation = new ServerPublicKeyCredentialAttestation();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => attestation!.Map());
    }

    [Test]
    public void Map_WhenAttestationValid_ThenReturnsPublicKeyCredentialAttestation()
    {
        // Arrange
        var attestation = new ServerPublicKeyCredentialAttestation
        {
            Id = "Id",
            RawId = "RawId",
            Response = new ServerAuthenticatorAttestationResponse
            {
                ClientDataJson = "ClientDataJson",
                AttestationObject = "AttestationObject",
                Signature = "Signature",
                UserHandler = "UserHandler",
            }
        };

        // Act
        var result = attestation.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Id, Is.EqualTo(attestation.Id));
        Assert.That(result.RawId, Is.EqualTo(attestation.RawId));
        Assert.That(result.Response.ClientDataJson, Is.EqualTo(attestation.Response.ClientDataJson));
        Assert.That(result.Response.AttestationObject, Is.EqualTo(attestation.Response.AttestationObject));
        Assert.That(result.Response.Signature, Is.EqualTo(attestation.Response.Signature));
        Assert.That(result.Response.UserHandler, Is.EqualTo(attestation.Response.UserHandler));
    }
}
