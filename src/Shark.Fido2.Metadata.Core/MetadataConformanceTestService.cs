using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core;

/// <summary>
/// See: https://github.com/fido-alliance/conformance-test-tools-resources/issues/422#issuecomment-508959572
/// </summary>
public sealed class MetadataConformanceTestService : IMetadataCachedService
{
    private const string KeyPrefix = "md";
    private const int DefaultExpirationInMinutes = 5;

    private static readonly SemaphoreSlim _semaphore = new(1, 1);

    private readonly IHttpClientConformanceTestRepository _httpClientRepository;
    private readonly IMetadataReaderService _metadataReaderService;
    private readonly IDistributedCache _cache;

    public MetadataConformanceTestService(
        IHttpClientConformanceTestRepository httpClientRepository,
        IMetadataReaderService metadataReaderService,
        IDistributedCache cache)
    {
        _httpClientRepository = httpClientRepository;
        _metadataReaderService = metadataReaderService;
        _cache = cache;
    }

    public async Task<MetadataBlobPayloadEntry?> Get(Guid aaguid, CancellationToken cancellationToken = default)
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
        return entry;
    }

    private async Task<string> Cache(CancellationToken cancellationToken)
    {
        var rootCertificate = await _httpClientRepository.GetRootCertificate(cancellationToken);

        var endpoints = await _httpClientRepository.GetMetadataBlobEndpoints(cancellationToken);

        List<MetadataBlobPayloadEntry> payloadEntries = [];

        foreach (var endpoint in endpoints)
        {
            try
            {
                var metadataBlob = await _httpClientRepository.GetMetadataBlob(endpoint, cancellationToken);

                var metadata = await _metadataReaderService.ValidateAndRead(
                    metadataBlob,
                    rootCertificate,
                    cancellationToken);

                payloadEntries.AddRange(metadata.Payload);
            }
            catch
            {
            }
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
