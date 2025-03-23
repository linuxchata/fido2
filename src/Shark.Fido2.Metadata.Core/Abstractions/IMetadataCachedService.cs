using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface IMetadataCachedService
{
    Task<MetadataBlobPayloadEntry?> Get(Guid aaguid, CancellationToken cancellationToken = default);
}
