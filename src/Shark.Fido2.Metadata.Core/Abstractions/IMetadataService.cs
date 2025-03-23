using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface IMetadataService
{
    Task<MetadataBlobPayload> Get(CancellationToken cancellationToken);
}
