using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.Runtime;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.DynamoDB;

/// <summary>
/// Amazon DynamoDB implementation of the credential repository.
/// </summary>
/// <remarks>
/// This implementation uses Amazon DynamoDB as the backing store for FIDO2 credentials.
/// The table structure uses 'cid' as the partition key and includes a GSI on 'un' (username).
/// </remarks>
internal sealed class CredentialRepository : ICredentialRepository
{
    private const string TableName = "Credential";
    private const string UserNameIndex = "UserNameIndex";

    private readonly IAmazonDynamoDB _client;

    public CredentialRepository(IAmazonDynamoDB client)
    {
        _client = client;
    }

    public async Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return null;
        }

        var request = new GetItemRequest
        {
            TableName = TableName,
            Key = new Dictionary<string, AttributeValue>
            {
                { AttributeNames.CredentialId, new AttributeValue { B = new MemoryStream(credentialId) } },
            },
            ConsistentRead = true,
        };

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
            KeyConditionExpression = $"{AttributeNames.UserName} = {ExpressionNames.UserName}",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                { ExpressionNames.UserName, new AttributeValue { S = username } },
            },
            ConsistentRead = false, // GSIs do not support consistent reads
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

        var request = new GetItemRequest
        {
            TableName = TableName,
            Key = new Dictionary<string, AttributeValue>
            {
                { AttributeNames.CredentialId, new AttributeValue { B = new MemoryStream(credentialId) } },
            },
            ProjectionExpression = AttributeNames.CredentialId,
            ConsistentRead = true,
        };

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

        var dateTimeString = GetDateTimeString();

        var request = new PutItemRequest
        {
            TableName = TableName,
            Item = entity.ToItem(dateTimeString),
        };

        var response = await _client.PutItemAsync(request, cancellationToken);

        ValidateResponse(response);
    }

    public async Task UpdateSignCount(byte[] credentialId, uint signCount, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        var dateTimeString = GetDateTimeString();

        var request = new UpdateItemRequest
        {
            TableName = TableName,
            Key = new Dictionary<string, AttributeValue>
            {
                { AttributeNames.CredentialId, new AttributeValue { B = new MemoryStream(credentialId) } },
            },
            UpdateExpression = $"SET {AttributeNames.SignCount} = {ExpressionNames.SignCount}, {AttributeNames.UpdatedAt} = {ExpressionNames.UpdatedAt}",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                { ExpressionNames.SignCount, new AttributeValue { N = $"{signCount}" } },
                { ExpressionNames.UpdatedAt, new AttributeValue { S = dateTimeString } },
            },
        };

        var response = await _client.UpdateItemAsync(request, cancellationToken);

        ValidateResponse(response);
    }

    private static string GetDateTimeString()
    {
        return DateTime.UtcNow.ToString("o");
    }

    private static void ValidateResponse(AmazonWebServiceResponse response)
    {
        if (response.HttpStatusCode != System.Net.HttpStatusCode.OK)
        {
            throw new InvalidOperationException("Request to DynamoDB did not complete successfully");
        }
    }
}
