using Microsoft.Extensions.Logging;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions.Repositories;
using Shark.Fido2.ConvenienceMetadata.Core.Models;

namespace Shark.Fido2.ConvenienceMetadata.Core.Services;

internal sealed class ConvenienceMetadataService : IConvenienceMetadataService
{
    private readonly IHttpClientRepository _httpClientRepository;
    private readonly IConvenienceMetadataReaderService _metadataReaderService;
    private readonly ILogger<ConvenienceMetadataService> _logger;

    public ConvenienceMetadataService(
        IHttpClientRepository httpClientRepository,
        IConvenienceMetadataReaderService metadataReaderService,
        ILogger<ConvenienceMetadataService> logger)
    {
        _httpClientRepository = httpClientRepository;
        _metadataReaderService = metadataReaderService;
        _logger = logger;
    }

    public async Task<ConvenienceMetadataPayload?> Get(CancellationToken cancellationToken)
    {
        try
        {
            var convenienceMetadataBlob = await _httpClientRepository.GetConvenienceMetadataBlob(cancellationToken);

            _logger.LogDebug("Convenience metadata BLOB was downloaded");

            return _metadataReaderService.Read(convenienceMetadataBlob);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to download or read convenience metadata BLOB from FIDO Convenience Metadata Service.");
            return null;
        }
    }
}
