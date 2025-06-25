using Amazon.DynamoDBv2.Model;
using Shark.Fido2.Core.Entities;

namespace Shark.Fido2.DynamoDB;

internal static class CredentialEntityMapper
{
    internal static CredentialEntity ToEntity(this Dictionary<string, AttributeValue> item)
    {
        return new CredentialEntity
        {
            CredentialId = item["cid"].B.ToArray(),
            UserHandle = item["uh"].B.ToArray(),
            UserName = item["un"].S,
            UserDisplayName = item["udn"].S,
            CredentialPublicKey = null!,
            CredentialPublicKeyJson = item["cpk"].S,
            SignCount = uint.Parse(item["sc"].N),
            Transports = item["tsp"].S,
            CreatedAt = DateTime.Parse(item["cat"].S),
            UpdatedAt = item.ContainsKey("uat") && !item["uat"].NULL == true
                ? DateTime.Parse(item["uat"].S)
                : null,
        };
    }

    internal static CredentialDescriptorEntity ToDescriptorEntity(this Dictionary<string, AttributeValue> item)
    {
        return new CredentialDescriptorEntity
        {
            CredentialId = item["cid"].B.ToArray(),
            UserName = item["un"].S,
            Transports = item["tsp"].S,
        };
    }

    internal static Dictionary<string, AttributeValue> ToItem(this CredentialEntity entity, string createdAt)
    {
        return new Dictionary<string, AttributeValue>
        {
            { "cid", new AttributeValue { B = new MemoryStream(entity.CredentialId) } },
            { "uh", new AttributeValue { B = new MemoryStream(entity.UserHandle) } },
            { "un", new AttributeValue { S = entity.UserName } },
            { "udn", new AttributeValue { S = entity.UserDisplayName } },
            { "cpk", new AttributeValue { S = entity.CredentialPublicKeyJson } },
            { "sc", new AttributeValue { N = $"{entity.SignCount}" } },
            { "tsp", new AttributeValue { S = entity.Transports } },
            { "cat", new AttributeValue { S = createdAt } },
            { "uat", new AttributeValue { NULL = true } },
        };
    }
}
