using Microsoft.Extensions.Logging;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Services;

internal sealed class MetadataService : IMetadataService
{
    private readonly IHttpClientRepository _httpClientRepository;
    private readonly IMetadataReaderService _metadataReaderService;
    private readonly ILogger<MetadataService> _logger;

    public MetadataService(
        IHttpClientRepository httpClientRepository,
        IMetadataReaderService metadataReaderService,
        ILogger<MetadataService> logger)
    {
        _httpClientRepository = httpClientRepository;
        _metadataReaderService = metadataReaderService;
        _logger = logger;
    }

    public async Task<MetadataBlobPayload> Get(CancellationToken cancellationToken)
    {
        // Step 1
        // Download and cache the root signing trust anchor from the respective MDS root location e.g.
        // More information can be found at https://fidoalliance.org/metadata/
        var rootCertificate = await _httpClientRepository.GetRootCertificate(cancellationToken);

        _logger.LogDebug(
            "Root certificate with subject '{Subject}' was downloaded",
            rootCertificate.Subject);

        // Step 3
        // The FIDO Server MUST be able to download the latest metadata BLOB object from the well-known URL when
        // appropriate, e.g. https://mds.fidoalliance.org/. The nextUpdate field of the Metadata BLOB specifies a
        // date when the download SHOULD occur at latest.
        var metadataBlob = await _httpClientRepository.GetMetadataBlob(cancellationToken);

        _logger.LogDebug("Metadata blob was downloaded");

        // Steps 4-7
        return await _metadataReaderService.ValidateAndRead(metadataBlob, rootCertificate, cancellationToken);
    }
}
