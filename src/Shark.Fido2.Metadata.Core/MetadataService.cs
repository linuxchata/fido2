using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core;

public sealed class MetadataService : IMetadataService
{
    private readonly IHttpClientRepository _httpClientRepository;
    private readonly IMetadataReaderService _metadataReaderService;

    public MetadataService(IHttpClientRepository httpClientRepository, IMetadataReaderService metadataReaderService)
    {
        _httpClientRepository = httpClientRepository;
        _metadataReaderService = metadataReaderService;
    }

    public async Task<MetadataBlobPayload> Get(CancellationToken cancellationToken)
    {
        // Step 1
        // Download and cache the root signing trust anchor from the respective MDS root location e.g.
        // More information can be found at https://fidoalliance.org/metadata/
        var rootCertificate = await _httpClientRepository.GetRootCertificate(cancellationToken);

        // Step 3
        // The FIDO Server MUST be able to download the latest metadata BLOB object from the well-known URL when
        // appropriate, e.g. https://mds.fidoalliance.org/. The nextUpdate field of the Metadata BLOB specifies a
        // date when the download SHOULD occur at latest.
        var metadataBlob = await _httpClientRepository.GetMetadataBlob(cancellationToken);

        // Steps 4-7
        return await _metadataReaderService.ValidateAndRead(metadataBlob, rootCertificate, cancellationToken);
    }
}
