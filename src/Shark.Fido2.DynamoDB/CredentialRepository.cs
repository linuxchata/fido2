using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;
using Shark.Fido2.DynamoDB.Abstractions;

namespace Shark.Fido2.DynamoDB;

internal sealed class CredentialRepository : ICredentialRepository
{
    private const string TableName = "Credential";
    private const string UserNameIndex = "UserNameIndex";
    private const string PartitionKey = "CredentialId";

    private readonly AmazonDynamoDBClient _client;

    public CredentialRepository(IAmazonDynamoDbClientFactory amazonDynamoDBClientFactory)
    {
        _client = amazonDynamoDBClientFactory.GetClient();
    }

    public async Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null)
        {
            return null;
        }

        var request = GetGetItemRequest(credentialId);

        var response = await _client.GetItemAsync(request, cancellationToken);

        if (response.Item != null && response.Item.Count > 0)
        {
            var entity = response.Item.ToEntity();

            return entity.ToDomain();
        }
        else
        {
            return null;
        }
    }

    public async Task<List<CredentialDescriptor>> Get(string username, CancellationToken cancellationToken = default)
    {
        var request = new QueryRequest
        {
            TableName = TableName,
            IndexName = UserNameIndex,
            KeyConditionExpression = "UserName = :v_userName",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                { ":v_userName", new AttributeValue { S = username } },
            },
            ConsistentRead = false, // GSIs do not support consistent reads
        };

        var response = await _client.QueryAsync(request, cancellationToken);

        if (response.Items.Count > 0)
        {
            var item = response.Items[0];
        }
        else
        {
            // Item not found
        }

        return new List<CredentialDescriptor>();
    }

    public async Task<bool> Exists(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null)
        {
            return false;
        }

        var request = GetGetItemRequest(credentialId);

        var response = await _client.GetItemAsync(request, cancellationToken);

        return response.Item != null && response.Item.Count > 0;
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var entity = credential.ToEntity();

        var request = new PutItemRequest
        {
            TableName = TableName,
            Item = entity.ToItem(),
        };

        var response = await _client.PutItemAsync(request, cancellationToken);

        if (response.HttpStatusCode != System.Net.HttpStatusCode.OK)
        {
            throw new Exception();
        }
    }

    public Task UpdateSignCount(Credential credential, uint signCount, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    private static GetItemRequest GetGetItemRequest(byte[] credentialId)
    {
        return new GetItemRequest
        {
            TableName = TableName,
            Key = new Dictionary<string, AttributeValue>
            {
                { PartitionKey, new AttributeValue { B = new MemoryStream(credentialId!) } },
            },
            ConsistentRead = true,
        };
    }
}
