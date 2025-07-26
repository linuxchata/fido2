using Shark.Fido2.Core.Entities;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.Mappers;

[TestFixture]
internal class CredentialMapperTests
{
    internal static readonly string[] ExpectedTransports = ["usb", "nfc"];

    [Test]
    public void ToEntity_WhenValidCredential_ThenReturnsCorrectEntity()
    {
        // Arrange
        var credential = new Credential
        {
            CredentialId = [1, 2, 3],
            UserHandle = [4, 5, 6],
            UserName = "testuser",
            UserDisplayName = "Test User",
            CredentialPublicKey = new CredentialPublicKey
            {
                KeyType = 1,
                Algorithm = 2,
                Modulus = [7, 8, 9],
                Exponent = [10, 11, 12],
                Curve = 13,
                XCoordinate = [14, 15, 16],
                YCoordinate = [17, 18, 19],
                Key = [20, 21, 22],
            },
            SignCount = 1,
            Transports = ["usb", "nfc"],
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
        };

        // Act
        var entity = credential.ToEntity();

        // Assert
        Assert.That(entity.CredentialId, Is.EqualTo(credential.CredentialId));
        Assert.That(entity.UserHandle, Is.EqualTo(credential.UserHandle));
        Assert.That(entity.UserName, Is.EqualTo(credential.UserName));
        Assert.That(entity.UserDisplayName, Is.EqualTo(credential.UserDisplayName));
        Assert.That(entity.SignCount, Is.EqualTo(credential.SignCount));
        Assert.That(entity.Transports, Is.EqualTo("usb;nfc"));
        Assert.That(entity.CreatedAt, Is.EqualTo(credential.CreatedAt));
        Assert.That(entity.UpdatedAt, Is.EqualTo(credential.UpdatedAt));

        // Verify CredentialPublicKey properties
        Assert.That(entity.CredentialPublicKey.KeyType, Is.EqualTo(credential.CredentialPublicKey.KeyType));
        Assert.That(entity.CredentialPublicKey.Algorithm, Is.EqualTo(credential.CredentialPublicKey.Algorithm));
        Assert.That(entity.CredentialPublicKey.Modulus, Is.EqualTo(credential.CredentialPublicKey.Modulus));
        Assert.That(entity.CredentialPublicKey.Exponent, Is.EqualTo(credential.CredentialPublicKey.Exponent));
        Assert.That(entity.CredentialPublicKey.Curve, Is.EqualTo(credential.CredentialPublicKey.Curve));
        Assert.That(entity.CredentialPublicKey.XCoordinate, Is.EqualTo(credential.CredentialPublicKey.XCoordinate));
        Assert.That(entity.CredentialPublicKey.YCoordinate, Is.EqualTo(credential.CredentialPublicKey.YCoordinate));
        Assert.That(entity.CredentialPublicKey.Key, Is.EqualTo(credential.CredentialPublicKey.Key));
    }

    [Test]
    public void ToDomain_WhenValidEntity_ThenReturnsCorrectDomainModel()
    {
        // Arrange
        var entity = new CredentialEntity
        {
            CredentialId = [1, 2, 3],
            UserHandle = [4, 5, 6],
            UserName = "testuser",
            UserDisplayName = "Test User",
            CredentialPublicKey = new CredentialPublicKeyEntity
            {
                KeyType = 1,
                Algorithm = 2,
                Modulus = [7, 8, 9],
                Exponent = [10, 11, 12],
                Curve = 13,
                XCoordinate = [14, 15, 16],
                YCoordinate = [17, 18, 19],
                Key = [20, 21, 22],
            },
            SignCount = 1,
            Transports = "usb;nfc",
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
        };

        // Act
        var domain = entity.ToDomain();

        // Assert
        Assert.That(domain, Is.Not.Null);
        Assert.That(domain!.CredentialId, Is.EqualTo(entity.CredentialId));
        Assert.That(domain.UserHandle, Is.EqualTo(entity.UserHandle));
        Assert.That(domain.UserName, Is.EqualTo(entity.UserName));
        Assert.That(domain.UserDisplayName, Is.EqualTo(entity.UserDisplayName));
        Assert.That(domain.SignCount, Is.EqualTo(entity.SignCount));
        Assert.That(domain.Transports, Is.EqualTo(ExpectedTransports));
        Assert.That(domain.CreatedAt, Is.EqualTo(entity.CreatedAt));
        Assert.That(domain.UpdatedAt, Is.EqualTo(entity.UpdatedAt));

        // Verify CredentialPublicKey properties
        Assert.That(domain.CredentialPublicKey.KeyType, Is.EqualTo(entity.CredentialPublicKey.KeyType));
        Assert.That(domain.CredentialPublicKey.Algorithm, Is.EqualTo(entity.CredentialPublicKey.Algorithm));
        Assert.That(domain.CredentialPublicKey.Modulus, Is.EqualTo(entity.CredentialPublicKey.Modulus));
        Assert.That(domain.CredentialPublicKey.Exponent, Is.EqualTo(entity.CredentialPublicKey.Exponent));
        Assert.That(domain.CredentialPublicKey.Curve, Is.EqualTo(entity.CredentialPublicKey.Curve));
        Assert.That(domain.CredentialPublicKey.XCoordinate, Is.EqualTo(entity.CredentialPublicKey.XCoordinate));
        Assert.That(domain.CredentialPublicKey.YCoordinate, Is.EqualTo(entity.CredentialPublicKey.YCoordinate));
        Assert.That(domain.CredentialPublicKey.Key, Is.EqualTo(entity.CredentialPublicKey.Key));
    }

    [Test]
    public void ToDomain_WhenEntityIsNull_ThenReturnsNull()
    {
        // Arrange
        CredentialEntity? entity = null;

        // Act
        var result = entity.ToDomain();

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void ToLightweightDomain_WhenValidEntity_ThenReturnsCorrectDomainModel()
    {
        // Arrange
        var entity = new CredentialDescriptorEntity
        {
            CredentialId = [1, 2, 3],
            UserName = "testuser",
            Transports = "usb;nfc",
        };

        // Act
        var result = entity.ToLightweightDomain();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.CredentialId, Is.EqualTo(entity.CredentialId));
        Assert.That(result.Transports, Is.EqualTo(ExpectedTransports));
    }

    [Test]
    public void ToLightweightDomain_WhenEntityIsNull_ThenReturnsNull()
    {
        // Arrange
        CredentialDescriptorEntity? entity = null;

        // Act
        var result = entity.ToLightweightDomain();

        // Assert
        Assert.That(result, Is.Null);
    }
}