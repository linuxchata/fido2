using System.Globalization;
using Amazon.DynamoDBv2.Model;
using Shark.Fido2.Core.Entities;

namespace Shark.Fido2.DynamoDB.Tests;

[TestFixture]
internal class CredentialEntityMapperTests
{
    private const string UserName = "UserName";
    private const string UserDisplayName = "DisplayName";
    private const string CredentialPublicKeyJson = "{'keyType':1,'algorithm':2}";
    private const uint SignCount = 42;
    private const string Transports = "usb;nfc";

    private static readonly byte[] CredentialId = [1, 2, 3, 4];
    private static readonly byte[] UserHandle = [5, 6, 7, 8];
    private static readonly DateTime CreatedAt = new(2025, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime UpdatedAt = new(2025, 1, 2, 12, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime LastUsedAt = new(2025, 1, 3, 12, 0, 0, DateTimeKind.Utc);

    [Test]
    public void ToEntity_WhenDatabaseItemIsValid_ThenReturnsCredentialEntity()
    {
        // Arrange
        var item = new Dictionary<string, AttributeValue>
        {
            { AttributeNames.CredentialId, new AttributeValue { B = new MemoryStream(CredentialId) } },
            { AttributeNames.UserHandle, new AttributeValue { B = new MemoryStream(UserHandle) } },
            { AttributeNames.UserName, new AttributeValue { S = UserName } },
            { AttributeNames.UserDisplayName, new AttributeValue { S = UserDisplayName } },
            { AttributeNames.CredentialPublicKeyJson, new AttributeValue { S = CredentialPublicKeyJson } },
            { AttributeNames.SignCount, new AttributeValue { N = SignCount.ToString() } },
            { AttributeNames.Transports, new AttributeValue { S = Transports } },
            { AttributeNames.CreatedAt, new AttributeValue { S = CreatedAt.ToString(DateTimeFormatInfo.InvariantInfo) } },
            { AttributeNames.UpdatedAt, new AttributeValue { S = UpdatedAt.ToString(DateTimeFormatInfo.InvariantInfo) } },
            { AttributeNames.LastUsedAt, new AttributeValue { S = LastUsedAt.ToString(DateTimeFormatInfo.InvariantInfo) } },
        };

        // Act
        var entity = item.ToEntity();

        // Assert
        Assert.That(entity.CredentialId, Is.EqualTo(CredentialId));
        Assert.That(entity.UserHandle, Is.EqualTo(UserHandle));
        Assert.That(entity.UserName, Is.EqualTo(UserName));
        Assert.That(entity.UserDisplayName, Is.EqualTo(UserDisplayName));
        Assert.That(entity.CredentialPublicKeyJson, Is.EqualTo(CredentialPublicKeyJson));
        Assert.That(entity.SignCount, Is.EqualTo(SignCount));
        Assert.That(entity.Transports, Is.EqualTo(Transports));
        Assert.That(entity.CreatedAt, Is.EqualTo(CreatedAt));
        Assert.That(entity.UpdatedAt, Is.EqualTo(UpdatedAt));
        Assert.That(entity.LastUsedAt, Is.EqualTo(LastUsedAt));
        Assert.That(entity.CredentialPublicKey, Is.Null);
    }

    [Test]
    public void ToEntity_WhenDatabaseItemIsValidAndNullableAttributesAreNull_ThenReturnsCredentialEntity()
    {
        // Arrange
        var item = new Dictionary<string, AttributeValue>
        {
            { AttributeNames.CredentialId, new AttributeValue { B = new MemoryStream(CredentialId) } },
            { AttributeNames.UserHandle, new AttributeValue { B = new MemoryStream(UserHandle) } },
            { AttributeNames.UserName, new AttributeValue { S = UserName } },
            { AttributeNames.UserDisplayName, new AttributeValue { S = UserDisplayName } },
            { AttributeNames.CredentialPublicKeyJson, new AttributeValue { S = CredentialPublicKeyJson } },
            { AttributeNames.SignCount, new AttributeValue { N = SignCount.ToString() } },
            { AttributeNames.Transports, new AttributeValue { S = Transports } },
            { AttributeNames.CreatedAt, new AttributeValue { S = CreatedAt.ToString(DateTimeFormatInfo.InvariantInfo) } },
            { AttributeNames.UpdatedAt, new AttributeValue { NULL = true } },
            { AttributeNames.LastUsedAt, new AttributeValue { NULL = true } },
        };

        // Act
        var entity = item.ToEntity();

        // Assert
        Assert.That(entity.UpdatedAt, Is.Null);
        Assert.That(entity.LastUsedAt, Is.Null);
        Assert.That(entity.CreatedAt, Is.EqualTo(CreatedAt));
    }

    [Test]
    public void ToEntity_WhenDatabaseItemIsValidAndNullableAttributesAreMissing_ThenReturnsCredentialEntity()
    {
        // Arrange
        var item = new Dictionary<string, AttributeValue>
        {
            { AttributeNames.CredentialId, new AttributeValue { B = new MemoryStream(CredentialId) } },
            { AttributeNames.UserHandle, new AttributeValue { B = new MemoryStream(UserHandle) } },
            { AttributeNames.UserName, new AttributeValue { S = UserName } },
            { AttributeNames.UserDisplayName, new AttributeValue { S = UserDisplayName } },
            { AttributeNames.CredentialPublicKeyJson, new AttributeValue { S = CredentialPublicKeyJson } },
            { AttributeNames.SignCount, new AttributeValue { N = SignCount.ToString() } },
            { AttributeNames.Transports, new AttributeValue { S = Transports } },
            { AttributeNames.CreatedAt, new AttributeValue { S = CreatedAt.ToString(DateTimeFormatInfo.InvariantInfo) } },
            //// UpdatedAt and LastUsedAt are missing
        };

        // Act
        var entity = item.ToEntity();

        // Assert
        Assert.That(entity.UpdatedAt, Is.Null);
        Assert.That(entity.LastUsedAt, Is.Null);
    }

    [Test]
    public void ToDescriptorEntity_WhenDatabaseItemIsValid_ThenReturnsCredentialDescriptorEntity()
    {
        // Arrange
        var item = new Dictionary<string, AttributeValue>
        {
            { AttributeNames.CredentialId, new AttributeValue { B = new MemoryStream(CredentialId) } },
            { AttributeNames.UserName, new AttributeValue { S = UserName } },
            { AttributeNames.Transports, new AttributeValue { S = Transports } },
        };

        // Act
        var entity = item.ToDescriptorEntity();

        // Assert
        Assert.That(entity.CredentialId, Is.EqualTo(CredentialId));
        Assert.That(entity.UserName, Is.EqualTo(UserName));
        Assert.That(entity.Transports, Is.EqualTo(Transports));
    }

    [Test]
    public void ToItem_WhenCredentialEntityIsValid_ThenReturnsDatabaseItem()
    {
        // Arrange
        var entity = new CredentialEntity
        {
            CredentialId = CredentialId,
            UserHandle = UserHandle,
            UserName = UserName,
            UserDisplayName = UserDisplayName,
            CredentialPublicKey = new CredentialPublicKeyEntity(),
            CredentialPublicKeyJson = CredentialPublicKeyJson,
            SignCount = SignCount,
            Transports = Transports,
            CreatedAt = CreatedAt,
            UpdatedAt = UpdatedAt,
            LastUsedAt = LastUsedAt,
        };
        var createdAtString = CreatedAt.ToString(DateTimeFormatInfo.InvariantInfo);

        // Act
        var item = entity.ToItem(createdAtString);

        // Assert
        Assert.That(item[AttributeNames.CredentialId].B.ToArray(), Is.EqualTo(CredentialId));
        Assert.That(item[AttributeNames.UserHandle].B.ToArray(), Is.EqualTo(UserHandle));
        Assert.That(item[AttributeNames.UserName].S, Is.EqualTo(UserName));
        Assert.That(item[AttributeNames.UserDisplayName].S, Is.EqualTo(UserDisplayName));
        Assert.That(item[AttributeNames.CredentialPublicKeyJson].S, Is.EqualTo(CredentialPublicKeyJson));
        Assert.That(item[AttributeNames.SignCount].N, Is.EqualTo(SignCount.ToString()));
        Assert.That(item[AttributeNames.Transports].S, Is.EqualTo(Transports));
        Assert.That(item[AttributeNames.CreatedAt].S, Is.EqualTo(createdAtString));
        Assert.That(item[AttributeNames.UpdatedAt].NULL, Is.True);
        Assert.That(item[AttributeNames.LastUsedAt].NULL, Is.True);
    }
}
