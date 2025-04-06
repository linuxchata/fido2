using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Domain;
using Shark.Fido2.Metadata.Core.Mappers;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Services;

internal sealed class MetadataCachedService : IMetadataCachedService
{
    private const string KeyPrefix = "md";
    private const int DefaultExpirationInMinutes = 30;

    private static readonly SemaphoreSlim _semaphore = new(1, 1);

    private readonly IMetadataService _metadataService;
    private readonly IDistributedCache _cache;
    private readonly TimeProvider _timeProvider;

    public MetadataCachedService(
        IMetadataService metadataService,
        IDistributedCache cache,
        TimeProvider timeProvider)
    {
        _metadataService = metadataService;
        _cache = cache;
        _timeProvider = timeProvider;
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

        var payload = JsonSerializer.Deserialize<List<MetadataBlobPayloadEntry>>(serializedPayload);

        var map = payload!.Where(p => p.Aaguid.HasValue).ToDictionary(p => p.Aaguid!.Value, p => p);
        map.TryGetValue(aaguid, out var entry);
        return entry?.ToDomain();
    }

    private async Task<string> Cache(CancellationToken cancellationToken)
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
            expiration = now.AddMinutes(DefaultExpirationInMinutes);
        }

        return expiration;
    }
}
