using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.ConvenienceMetadata.Core.Domain;
using Shark.Fido2.ConvenienceMetadata.Core.Models;

namespace Shark.Fido2.ConvenienceMetadata.Core.Services;

internal sealed class ConvenienceMetadataCachedService : IConvenienceMetadataCachedService
{
    private const string KeyPrefix = "cmd";
    private const int DefaultDistributedCacheExpirationInMinutes = 30;
    private const int DefaultMemoryCacheExpirationInMinutes = 10;

    private static readonly SemaphoreSlim OperationLock = new(1, 1);

    private readonly IConvenienceMetadataService _metadataService;
    private readonly IDistributedCache _cache;
    private readonly IMemoryCache _memoryCache;
    private readonly TimeProvider _timeProvider;

    public ConvenienceMetadataCachedService(
        IConvenienceMetadataService metadataService,
        IDistributedCache cache,
        IMemoryCache memoryCache,
        TimeProvider timeProvider)
    {
        _metadataService = metadataService;
        _cache = cache;
        _memoryCache = memoryCache;
        _timeProvider = timeProvider;
    }

    public async Task<ConvenienceMetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken)
    {
        var memoryCacheKey = $"{KeyPrefix}_{aaguid}";
        if (_memoryCache.TryGetValue(memoryCacheKey, out ConvenienceMetadataPayloadItem? cachedItem))
        {
            return cachedItem;
        }

        await OperationLock.WaitAsync(cancellationToken);

        string? serializedPayload;
        try
        {
            serializedPayload = await _cache.GetStringAsync(KeyPrefix, cancellationToken);
            serializedPayload ??= await StoreCacheInDistributedCache(cancellationToken);
        }
        finally
        {
            OperationLock.Release();
        }

        var metadataPayloadItem = GetMetadataPayloadItem(serializedPayload, aaguid);

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

        var serializedPayload = JsonSerializer.Serialize(metadata?.Entries);

        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = GetAbsoluteExpiration(),
        };

        if (serializedPayload != null)
        {
            await _cache.SetStringAsync(KeyPrefix, serializedPayload, options, cancellationToken);
        }

        return serializedPayload ?? string.Empty;
    }

    private DateTimeOffset GetAbsoluteExpiration()
    {
        return _timeProvider.GetUtcNow().AddMinutes(DefaultDistributedCacheExpirationInMinutes);
    }

    private static ConvenienceMetadataPayloadItem? GetMetadataPayloadItem(string serializedPayload, Guid aaguid)
    {
        if (string.IsNullOrWhiteSpace(serializedPayload))
        {
            return null;
        }

        var entries = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(serializedPayload);
        if (entries != null && entries.TryGetValue(aaguid.ToString(), out var entry))
        {
            var details = entry.Deserialize<ConvenienceDetails>();
            if (details != null)
            {
                return new ConvenienceMetadataPayloadItem
                {
                    Aaguid = aaguid,
                    FriendlyNames = details.FriendlyNames ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                    Icon = details.Icon,
                    IconDark = details.IconDark,
                    ProviderLogoLight = details.ProviderLogoLight,
                    ProviderLogoDark = details.ProviderLogoDark,
                };
            }
        }

        return null;
    }
}
