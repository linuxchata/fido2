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
    private const string KeyPrefix = "md";
    private const int DefaultDistributedCacheExpirationInMinutes = 30;
    private const int DefaultMemoryCacheExpirationInMinutes = 10;

    private static readonly SemaphoreSlim _operationLock = new(1, 1);

    private readonly IMetadataService _metadataService;
    private readonly IDistributedCache _cache;
    private readonly IMemoryCache _memoryCache;
    private readonly TimeProvider _timeProvider;

    public MetadataCachedService(
        IMetadataService metadataService,
        IDistributedCache cache,
        IMemoryCache memoryCache,
        TimeProvider timeProvider)
    {
        _metadataService = metadataService;
        _cache = cache;
        _memoryCache = memoryCache;
        _timeProvider = timeProvider;
    }

    public async Task<MetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken = default)
    {
        // Check memory cache
        var memoryCacheKey = $"{KeyPrefix}_{aaguid}";
        if (_memoryCache.TryGetValue(memoryCacheKey, out MetadataPayloadItem? cachedItem))
        {
            return cachedItem;
        }

        // Then check distributed cache
        await _operationLock.WaitAsync(cancellationToken);

        string? serializedPayload = null;

        try
        {
            serializedPayload = await _cache.GetStringAsync(KeyPrefix, cancellationToken);
            serializedPayload ??= await StoreCacheInDistributedCache(cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }

        var metadataPayloadItem = GetMetadataPayloadItem(serializedPayload, aaguid);

        // Cache the result in memory if found
        if (metadataPayloadItem != null)
        {
            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(DateTime.UtcNow.AddMinutes(DefaultMemoryCacheExpirationInMinutes));

            _memoryCache.Set(memoryCacheKey, metadataPayloadItem, cacheOptions);
        }

        return metadataPayloadItem;
    }

    private async Task<string> StoreCacheInDistributedCache(CancellationToken cancellationToken)
    {
        var metadata = await _metadataService.Get(cancellationToken);

        var serializedPayload = JsonSerializer.Serialize(metadata.Payload);

        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = GetAbsoluteExpiration(metadata.NextUpdate),
        };

        await _cache.SetStringAsync(KeyPrefix, serializedPayload, options, cancellationToken);

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

    private MetadataPayloadItem? GetMetadataPayloadItem(string serializedPayload, Guid aaguid)
    {
        var payload = JsonSerializer.Deserialize<List<MetadataBlobPayloadEntry>>(serializedPayload);
        var map = payload!.Where(p => p.Aaguid.HasValue).ToDictionary(p => p.Aaguid!.Value, p => p);
        map.TryGetValue(aaguid, out var item);
        return item?.ToDomain();
    }
}
