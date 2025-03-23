using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core;

public sealed class MetadataCachedService : IMetadataCachedService
{
    private const string KeyPrefix = "md";

    private static readonly SemaphoreSlim _semaphore = new(1, 1);

    private readonly IMetadataService _metadataService;
    private readonly IDistributedCache _cache;

    public MetadataCachedService(IMetadataService metadataService, IDistributedCache cache)
    {
        _metadataService = metadataService;
        _cache = cache;
    }

    public async Task<MetadataBlobPayloadEntry?> Get(Guid aaguid, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);

        string? serializedPayload = null;

        try
        {
            serializedPayload = await _cache.GetStringAsync(KeyPrefix, cancellationToken);
            if (serializedPayload == null)
            {
                var metadata = await _metadataService.Get(cancellationToken);

                serializedPayload = JsonSerializer.Serialize(metadata.Payload);

                var options = new DistributedCacheEntryOptions
                {
                    AbsoluteExpiration = new DateTimeOffset(metadata.Expiration),
                };

                await _cache.SetStringAsync(KeyPrefix, serializedPayload, options, cancellationToken);
            }
        }
        finally
        {
            _semaphore.Release();
        }

        var payload = JsonSerializer.Deserialize<List<MetadataBlobPayloadEntry>>(serializedPayload);
        return payload?.FirstOrDefault(x => x.Aaguid == aaguid);
    }
}
