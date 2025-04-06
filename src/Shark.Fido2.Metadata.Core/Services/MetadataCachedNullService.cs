using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Domain;

namespace Shark.Fido2.Metadata.Core.Services;

internal sealed class MetadataCachedNullService : IMetadataCachedService
{
    public Task<MetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken = default)
    {
        return Task.FromResult((MetadataPayloadItem?)null);
    }
}
