using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Domain;
using Shark.Fido2.DynamoDB.Abstractions;

namespace Shark.Fido2.DynamoDB;

internal sealed class CredentialRepository : ICredentialRepository
{
    private const string TableName = "Credential2";
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

        var request = new GetItemRequest
        {
            TableName = TableName,
            Key = new Dictionary<string, AttributeValue>
            {
                { PartitionKey, new AttributeValue { B = new MemoryStream(credentialId!) } },
            },
        };

        try
        {
            var response = await _client.GetItemAsync(request, cancellationToken);

            if (response.Item != null && response.Item.Count > 0)
            {
                Console.WriteLine("Item found:");
                foreach (var kvp in response.Item)
                {
                    Console.WriteLine($"{kvp.Key}: {kvp.Value.S ?? kvp.Value.N}");
                }

                return null;
            }
            else
            {
                return null;
            }
        }
        catch (Exception)
        {
            return null;
        }
    }

    public Task<List<CredentialDescriptor>> Get(string username, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new List<CredentialDescriptor>());
    }

    public Task<bool> Exists(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(false);
    }

    public Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    public Task UpdateSignCount(Credential credential, uint signCount, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}
