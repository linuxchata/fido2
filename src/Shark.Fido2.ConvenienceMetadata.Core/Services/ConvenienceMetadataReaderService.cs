using System.Text.Json;
using Microsoft.Extensions.Logging;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.ConvenienceMetadata.Core.Models;

namespace Shark.Fido2.ConvenienceMetadata.Core.Services;

internal sealed class ConvenienceMetadataReaderService : IConvenienceMetadataReaderService
{
    private readonly ILogger<ConvenienceMetadataReaderService> _logger;

    public ConvenienceMetadataReaderService(ILogger<ConvenienceMetadataReaderService> logger)
    {
        _logger = logger;
    }

    public ConvenienceMetadataPayload Read(string metadataBlob)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(metadataBlob);

        var payload = JsonSerializer.Deserialize<ConvenienceMetadataPayload>(metadataBlob);
        if (payload == null)
        {
            throw new InvalidDataException(
                "Failed to deserialize convenience metadata BLOB from FIDO Convenience Metadata Service.");
        }

        _logger.LogDebug("Convenience metadata BLOB payload is read");

        return payload;
    }
}
