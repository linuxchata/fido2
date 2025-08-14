using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Models.Tests.Mappers;

[TestFixture]
internal class PublicKeyCredentialAttestationMapperTests
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
        var attestation = new ServerPublicKeyCredentialAttestation
        {
            Id = "Id",
            RawId = "RawId",
            Response = null!,
            Type = "public-key",
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => attestation.Map());
    }

    [Test]
    public void Map_WhenAttestationIsValid_ThenReturnsPublicKeyCredentialAttestation()
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
            },
            Type = "public-key",
        };

        // Act
        var result = attestation.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Id, Is.EqualTo(attestation.Id));
        Assert.That(result.RawId, Is.EqualTo(attestation.RawId));
        Assert.That(result.Response.ClientDataJson, Is.EqualTo(attestation.Response.ClientDataJson));
        Assert.That(result.Response.AttestationObject, Is.EqualTo(attestation.Response.AttestationObject));
        Assert.That(result.Type, Is.EqualTo(attestation.Type));
        Assert.That(result.Extensions, Is.Not.Null);
    }

    [Test]
    public void Map_WhenAttestationIsValidAndHasExtensions_ThenReturnsPublicKeyCredentialAttestation()
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
                Transports = ["usb", "nfc"],
            },
            Type = "public-key",
            Extensions = new ServerAuthenticationExtensionsClientOutputs
            {
                AppIdExclude = true,
                UserVerificationMethod = [[1236]],
                CredentialProperties = new ServerCredentialPropertiesOutput
                {
                    RequireResidentKey = true,
                },
                LargeBlob = new ServerAuthenticationExtensionsLargeBlobOutputs
                {
                    Supported = true,
                    Blob = System.Text.Encoding.ASCII.GetBytes("blob-data"),
                },
            },
        };

        // Act
        var result = attestation.Map();

        // Assert
        Assert.That(result.Extensions, Is.Not.Null);
        Assert.That(result.Extensions.AppIdExclude, Is.EqualTo(attestation.Extensions.AppIdExclude));
        Assert.That(result.Extensions.UserVerificationMethod, Is.EqualTo(attestation.Extensions.UserVerificationMethod));
        Assert.That(result.Extensions.CredentialProperties, Is.Not.Null);
        Assert.That(result.Extensions.CredentialProperties.RequireResidentKey, Is.EqualTo(attestation.Extensions.CredentialProperties.RequireResidentKey));
        Assert.That(result.Extensions.LargeBlob, Is.Not.Null);
        Assert.That(result.Extensions.LargeBlob!.Supported, Is.EqualTo(attestation.Extensions.LargeBlob.Supported));
        Assert.That(result.Extensions.LargeBlob.Blob, Is.EqualTo(attestation.Extensions.LargeBlob.Blob));
    }
}
