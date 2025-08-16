using System.Globalization;
using Amazon.DynamoDBv2.Model;
using Shark.Fido2.Core.Entities;

namespace Shark.Fido2.DynamoDB;

internal static class CredentialEntityMapper
{
    internal static CredentialEntity ToEntity(this Dictionary<string, AttributeValue> item)
    {
        return new CredentialEntity
        {
            CredentialId = item[AttributeNames.CredentialId].B.ToArray(),
            UserHandle = item[AttributeNames.UserHandle].B.ToArray(),
            UserName = item[AttributeNames.UserName].S,
            UserDisplayName = item[AttributeNames.UserDisplayName].S,
            CredentialPublicKey = null!,
            CredentialPublicKeyJson = item[AttributeNames.CredentialPublicKeyJson].S,
            SignCount = uint.Parse(item[AttributeNames.SignCount].N),
            Transports = item[AttributeNames.Transports].S,
            CreatedAt = GetDateTime(item, AttributeNames.CreatedAt),
            UpdatedAt = GetNullableDateTime(item, AttributeNames.UpdatedAt),
            LastUsedAt = GetNullableDateTime(item, AttributeNames.LastUsedAt),
        };
    }

    internal static CredentialDescriptorEntity ToDescriptorEntity(this Dictionary<string, AttributeValue> item)
    {
        return new CredentialDescriptorEntity
        {
            CredentialId = item[AttributeNames.CredentialId].B.ToArray(),
            UserName = item[AttributeNames.UserName].S,
            Transports = item[AttributeNames.Transports].S,
        };
    }

    internal static Dictionary<string, AttributeValue> ToItem(this CredentialEntity entity, string createdAt)
    {
        return new Dictionary<string, AttributeValue>
        {
            { AttributeNames.CredentialId, new AttributeValue { B = new MemoryStream(entity.CredentialId) } },
            { AttributeNames.UserHandle, new AttributeValue { B = new MemoryStream(entity.UserHandle) } },
            { AttributeNames.UserName, new AttributeValue { S = entity.UserName } },
            { AttributeNames.UserDisplayName, new AttributeValue { S = entity.UserDisplayName } },
            { AttributeNames.CredentialPublicKeyJson, new AttributeValue { S = entity.CredentialPublicKeyJson } },
            { AttributeNames.SignCount, new AttributeValue { N = $"{entity.SignCount}" } },
            { AttributeNames.Transports, new AttributeValue { S = entity.Transports } },
            { AttributeNames.CreatedAt, new AttributeValue { S = createdAt } },
            { AttributeNames.UpdatedAt, new AttributeValue { NULL = true } },
            { AttributeNames.LastUsedAt, new AttributeValue { NULL = true } },
        };
    }

    private static DateTime GetDateTime(Dictionary<string, AttributeValue> item, string attributeName)
    {
        return DateTime.Parse(item[attributeName].S, DateTimeFormatInfo.InvariantInfo);
    }

    private static DateTime? GetNullableDateTime(Dictionary<string, AttributeValue> item, string attributeName)
    {
        if (item.TryGetValue(attributeName, out AttributeValue? value) && value != null && value.S != null)
        {
            return DateTime.Parse(value.S, DateTimeFormatInfo.InvariantInfo);
        }

        return null;
    }
}
