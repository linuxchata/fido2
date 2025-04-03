using Shark.Fido2.Metadata.Core.Domain;

namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface IMetadataCachedService
{
    Task<MetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken = default);
}
