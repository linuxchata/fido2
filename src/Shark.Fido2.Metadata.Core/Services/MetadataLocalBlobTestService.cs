using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Configurations;
using Shark.Fido2.Metadata.Core.Domain;
using Shark.Fido2.Metadata.Core.Mappers;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Services;

/// <summary>
/// Local blob test service is used for conformance testing for make creadentials and get assertion test cases.
/// </summary>
internal sealed class MetadataLocalBlobTestService : IMetadataCachedService
{
    private const string KeyPrefix = "md";
    private const int DefaultExpirationInMinutes = 5;

    private static readonly SemaphoreSlim _semaphore = new(1, 1);

    private readonly IDistributedCache _cache;
    private readonly MetadataServiceConfiguration _configuration;

    public MetadataLocalBlobTestService(IDistributedCache cache, IOptions<MetadataServiceConfiguration> options)
    {
        _cache = cache;
        _configuration = options.Value;
    }

    public async Task<MetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);

        string? serializedPayload = null;

        try
        {
            serializedPayload = await _cache.GetStringAsync(KeyPrefix, cancellationToken);
            serializedPayload ??= await Cache(cancellationToken);
        }
        finally
        {
            _semaphore.Release();
        }

        var payloadEntries = JsonSerializer.Deserialize<List<MetadataStatement>>(serializedPayload);

        var map = payloadEntries!.ToDictionary(p => p.Aaguid, p => p);
        map.TryGetValue(aaguid, out var entry);
        return entry?.ToDomain();
    }

    private async Task<string> Cache(CancellationToken cancellationToken)
    {
        var directoryPath = _configuration.MetadataBlobLocation;
        var payloadEntries = new List<MetadataStatement>();
        if (Directory.Exists(directoryPath))
        {
            var metadataBlobs = Directory.GetFiles(directoryPath, "*.json");

            foreach (string metadataBlob in metadataBlobs)
            {
                var metadata = File.ReadAllText(metadataBlob);
                var payloadEntry = JsonSerializer.Deserialize<MetadataStatement>(metadata);
                payloadEntries.Add(payloadEntry!);
            }
        }
        else
        {
            throw new Exception($"Path '{directoryPath}' does not exist");
        }

        var serializedPayload = JsonSerializer.Serialize(payloadEntries);

        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = DateTime.UtcNow.AddMinutes(DefaultExpirationInMinutes),
        };

        await _cache.SetStringAsync(KeyPrefix, serializedPayload, options, cancellationToken);

        return serializedPayload;
    }
}
