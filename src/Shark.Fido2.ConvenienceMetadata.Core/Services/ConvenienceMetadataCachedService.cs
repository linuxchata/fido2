using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.ConvenienceMetadata.Core.Configurations;
using Shark.Fido2.ConvenienceMetadata.Core.Domain;
using Shark.Fido2.ConvenienceMetadata.Core.Models;

namespace Shark.Fido2.ConvenienceMetadata.Core.Services;

internal sealed class ConvenienceMetadataCachedService : IConvenienceMetadataCachedService
{
    private const string CacheKey = "cmds_payload";
    private const string KeyPrefix = "cmds";
    private const int DefaultMemoryCacheExpirationInMinutes = 10;

    private static readonly SemaphoreSlim OperationLock = new(1, 1);

    private readonly IConvenienceMetadataService _convenienceMetadataService;
    private readonly IDistributedCache _distributedCache;
    private readonly IMemoryCache _memoryCache;
    private readonly TimeProvider _timeProvider;
    private readonly ConvenienceMetadataServiceConfiguration _configuration;

    public ConvenienceMetadataCachedService(
        IConvenienceMetadataService convenienceMetadataService,
        IDistributedCache distributedCache,
        IMemoryCache memoryCache,
        TimeProvider timeProvider,
        IOptions<ConvenienceMetadataServiceConfiguration> options)
    {
        _convenienceMetadataService = convenienceMetadataService;
        _distributedCache = distributedCache;
        _memoryCache = memoryCache;
        _timeProvider = timeProvider;
        _configuration = options.Value;
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
            serializedPayload = await _distributedCache.GetStringAsync(CacheKey, cancellationToken);
            serializedPayload ??= await StoreInDistributedCache(cancellationToken);
        }
        finally
        {
            OperationLock.Release();
        }

        var payloadItem = GetMetadataPayloadItem(serializedPayload, aaguid);

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
        var convenienceMetadata = await _convenienceMetadataService.Get(cancellationToken);

        var serializedPayload = JsonSerializer.Serialize(convenienceMetadata?.Entries);

        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = GetAbsoluteExpiration(),
        };

        if (string.Equals(serializedPayload, "null", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        await _distributedCache.SetStringAsync(CacheKey, serializedPayload, options, cancellationToken);
        return serializedPayload;
    }

    private DateTimeOffset GetAbsoluteExpiration()
    {
        return _timeProvider.GetUtcNow().Add(_configuration.CacheExpiration);
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
                    FriendlyNames = details.FriendlyNames,
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
