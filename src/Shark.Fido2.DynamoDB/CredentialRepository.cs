using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.Runtime;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;
using Shark.Fido2.DynamoDB.Abstractions;

namespace Shark.Fido2.DynamoDB;

/// <summary>
/// Amazon DynamoDB implementation of the credential repository.
/// </summary>
/// <remarks>
/// This implementation uses Amazon DynamoDB as the backing store for FIDO2 credentials.
/// The table structure uses 'cid' as the partition key and includes a GSI on 'un' (username).
/// </remarks>
internal sealed class CredentialRepository : ICredentialRepository, IDisposable
{
    private const string TableName = "Credential";
    private const string UserNameIndex = "UserNameIndex";
    private const string PartitionKey = "cid";
    private const int QueryLimit = 100;

    private readonly AmazonDynamoDBClient _client;

    public CredentialRepository(IAmazonDynamoDbClientFactory amazonDynamoDBClientFactory)
    {
        _client = amazonDynamoDBClientFactory.GetClient();
    }

    public async Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return null;
        }

        var request = GetGetItemRequest(credentialId);

        var response = await _client.GetItemAsync(request, cancellationToken);

        ValidateResponse(response);

        if (response.Item != null && response.Item.Count > 0)
        {
            var entity = response.Item.ToEntity();

            return entity.ToDomain();
        }

        return null;
    }

    public async Task<List<CredentialDescriptor>> Get(string username, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(username))
        {
            return [];
        }

        var request = new QueryRequest
        {
            TableName = TableName,
            IndexName = UserNameIndex,
            KeyConditionExpression = "un = :userName",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                { ":userName", new AttributeValue { S = username } },
            },
            ConsistentRead = false, // GSIs do not support consistent reads
            Limit = QueryLimit,
        };

        var response = await _client.QueryAsync(request, cancellationToken);

        ValidateResponse(response);

        if (response.Items.Count > 0)
        {
            var entities = response.Items.Select(e => e.ToDescriptorEntity());

            return entities.Select(e => e.ToLightweightDomain()!).ToList();
        }

        return [];
    }

    public async Task<bool> Exists(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return false;
        }

        var request = GetGetItemRequest(credentialId);

        var response = await _client.GetItemAsync(request, cancellationToken);

        ValidateResponse(response);

        return response.Item != null && response.Item.Count > 0;
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(credential.CredentialId);
        ArgumentNullException.ThrowIfNullOrEmpty(credential.UserName);
        ArgumentNullException.ThrowIfNull(credential.UserHandle);
        ArgumentNullException.ThrowIfNull(credential.CredentialPublicKey);

        var entity = credential.ToEntity();

        var request = new PutItemRequest
        {
            TableName = TableName,
            Item = entity.ToItem(GetDateTimeString()),
        };

        var response = await _client.PutItemAsync(request, cancellationToken);

        ValidateResponse(response);
    }

    public async Task UpdateSignCount(byte[] credentialId, uint signCount, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        var request = new UpdateItemRequest
        {
            TableName = TableName,
            Key = new Dictionary<string, AttributeValue>
            {
                { PartitionKey, new AttributeValue { B = new MemoryStream(credentialId) } },
            },
            UpdateExpression = "SET sc = :signCount, uat = :updatedAt",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                { ":signCount", new AttributeValue { N = $"{signCount}" } },
                { ":updatedAt", new AttributeValue { S = GetDateTimeString() } },
            },
        };

        var response = await _client.UpdateItemAsync(request, cancellationToken);

        ValidateResponse(response);
    }

    public void Dispose()
    {
        _client.Dispose();
    }

    private static GetItemRequest GetGetItemRequest(byte[] credentialId)
    {
        return new GetItemRequest
        {
            TableName = TableName,
            Key = new Dictionary<string, AttributeValue>
            {
                { PartitionKey, new AttributeValue { B = new MemoryStream(credentialId) } },
            },
            ConsistentRead = true,
        };
    }

    private static string GetDateTimeString()
    {
        return DateTime.UtcNow.ToString("o");
    }

    private void ValidateResponse(AmazonWebServiceResponse response)
    {
        if (response.HttpStatusCode != System.Net.HttpStatusCode.OK)
        {
            throw new InvalidOperationException("Request to DynamoDB did not complete successfully");
        }
    }
}
