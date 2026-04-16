using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Domain;
using Shark.Fido2.Metadata.Core.Mappers;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Services;

internal sealed class MetadataCachedService : IMetadataCachedService
{
    private const string CacheKey = "mds_payload";
    private const string KeyPrefix = "mds";
    private const int DefaultDistributedCacheExpirationInMinutes = 30;
    private const int DefaultMemoryCacheExpirationInMinutes = 10;

    private static readonly SemaphoreSlim OperationLock = new(1, 1);

    private readonly IMetadataService _metadataService;
    private readonly IDistributedCache _distributedCache;
    private readonly IMemoryCache _memoryCache;
    private readonly TimeProvider _timeProvider;

    public MetadataCachedService(
        IMetadataService metadataService,
        IDistributedCache distributedCache,
        IMemoryCache memoryCache,
        TimeProvider timeProvider)
    {
        _metadataService = metadataService;
        _distributedCache = distributedCache;
        _memoryCache = memoryCache;
        _timeProvider = timeProvider;
    }

    public async Task<MetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken)
    {
        // Check memory cache
        var memoryCacheKey = $"{KeyPrefix}_{aaguid}";
        if (_memoryCache.TryGetValue(memoryCacheKey, out MetadataPayloadItem? cachedItem))
        {
            return cachedItem;
        }

        // Then check distributed cache
        await OperationLock.WaitAsync(cancellationToken);

        string? serializedPayload;

        try
        {
            serializedPayload = await _distributedCache.GetStringAsync(CacheKey, cancellationToken);
            serializedPayload ??= await StoreInDistributedCache(cancellationToken);
        }
        finally
        {
            OperationLock.Release();
        }

        var payloadItem = GetMetadataPayloadItem(serializedPayload, aaguid);

        // Cache the result in memory if found
        if (payloadItem != null)
        {
            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(DateTime.UtcNow.AddMinutes(DefaultMemoryCacheExpirationInMinutes));

            _memoryCache.Set(memoryCacheKey, payloadItem, cacheOptions);
        }

        return payloadItem;
    }

    private async Task<string> StoreInDistributedCache(CancellationToken cancellationToken)
    {
        var metadata = await _metadataService.Get(cancellationToken);

        var serializedPayload = JsonSerializer.Serialize(metadata.Payload);

        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = GetAbsoluteExpiration(metadata.NextUpdate),
        };

        await _distributedCache.SetStringAsync(CacheKey, serializedPayload, options, cancellationToken);

        return serializedPayload;
    }

    private DateTimeOffset GetAbsoluteExpiration(DateTime nextUpdate)
    {
        var expiration = new DateTimeOffset(nextUpdate);

        // The metadata BLOB object only contains the date of the next update, so the exact availability time
        // of the next object is unknown. If a new object is unavailable, retain the "old" Metadata BLOB object
        // for a short period.
        var now = _timeProvider.GetUtcNow();
        if (nextUpdate.Date == now.Date)
        {
            expiration = now.AddMinutes(DefaultDistributedCacheExpirationInMinutes);
        }

        return expiration;
    }

    private static MetadataPayloadItem? GetMetadataPayloadItem(string serializedPayload, Guid aaguid)
    {
        var payload = JsonSerializer.Deserialize<List<MetadataBlobPayloadEntry>>(serializedPayload);
        var map = payload!.Where(p => p.Aaguid.HasValue).ToDictionary(p => p.Aaguid!.Value, p => p);
        map.TryGetValue(aaguid, out var item);
        return item?.ToDomain();
    }
}
