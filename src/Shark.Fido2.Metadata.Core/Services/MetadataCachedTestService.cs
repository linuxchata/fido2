using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Configurations;
using Shark.Fido2.Metadata.Core.Domain;
using Shark.Fido2.Metadata.Core.Mappers;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Services;

/// <summary>
/// Remote blob test service is used for conformance testing for metadata service test cases.
/// See: https://github.com/fido-alliance/conformance-test-tools-resources/issues/422#issuecomment-508959572.
/// </summary>
internal sealed class MetadataCachedTestService : IMetadataCachedService
{
    private const string KeyPrefix = "md";
    private const int DefaultExpirationInMinutes = 5;

    private static readonly SemaphoreSlim _semaphore = new(1, 1);

    private readonly IHttpClientConformanceTestRepository _httpClientRepository;
    private readonly IMetadataReaderService _metadataReaderService;
    private readonly IDistributedCache _cache;
    private readonly MetadataServiceConfiguration _configuration;

    public MetadataCachedTestService(
        IHttpClientConformanceTestRepository httpClientRepository,
        IMetadataReaderService metadataReaderService,
        IDistributedCache cache,
        IOptions<MetadataServiceConfiguration> options)
    {
        _httpClientRepository = httpClientRepository;
        _metadataReaderService = metadataReaderService;
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

        var payloadEntries = JsonSerializer.Deserialize<List<MetadataBlobPayloadEntry>>(serializedPayload);

        var map = payloadEntries!.Where(p => p.Aaguid.HasValue).ToDictionary(p => p.Aaguid!.Value, p => p);
        map.TryGetValue(aaguid, out var entry);
        return entry?.ToDomain();
    }

    private async Task<string> Cache(CancellationToken cancellationToken)
    {
        var metadataBlobLocation = _configuration.MetadataBlobLocation.Split(';');
        if (metadataBlobLocation.Length != 2)
        {
            throw new FormatException("Metadata blob location should be in the format 'remoteUrl;localPath'");
        }

        var remoteUrl = metadataBlobLocation[0];
        var localPath = metadataBlobLocation[1];

        var remote = await GetRemote(remoteUrl, cancellationToken);
        var local = GetLocal(localPath);

        var payloadEntries = remote.Concat(local).ToList();

        var serializedPayload = JsonSerializer.Serialize(payloadEntries);

        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = DateTime.UtcNow.AddMinutes(DefaultExpirationInMinutes),
        };

        await _cache.SetStringAsync(KeyPrefix, serializedPayload, options, cancellationToken);

        return serializedPayload;
    }

    private async Task<List<MetadataBlobPayloadEntry>> GetRemote(string remoteUrl, CancellationToken cancellationToken)
    {
        var rootCertificate = await _httpClientRepository.GetRootCertificate(
            _configuration.RootCertificateLocationUrl,
            cancellationToken);

        var endpoints = await _httpClientRepository.GetMetadataBlobEndpoints(remoteUrl, cancellationToken);

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

        return payloadEntries;
    }

    private List<MetadataBlobPayloadEntry> GetLocal(string localPath)
    {
        var metadataStatements = new List<MetadataStatement>();
        if (Directory.Exists(localPath))
        {
            var metadataBlobs = Directory.GetFiles(localPath, "*.json");

            foreach (string metadataBlob in metadataBlobs)
            {
                var metadata = File.ReadAllText(metadataBlob);
                var payloadEntry = JsonSerializer.Deserialize<MetadataStatement>(metadata);
                metadataStatements.Add(payloadEntry!);
            }
        }
        else
        {
            throw new InvalidOperationException($"Path '{localPath}' does not exist");
        }

        var payloadEntries = metadataStatements
            .Select(e =>
                new MetadataBlobPayloadEntry
                {
                    Aaguid = e.Aaguid,
                    MetadataStatement = e,
                    StatusReports = [],
                    TimeOfLastStatusChange = DateTime.UtcNow.Date.ToShortDateString(),
                })
            .ToList();

        return payloadEntries;
    }
}
