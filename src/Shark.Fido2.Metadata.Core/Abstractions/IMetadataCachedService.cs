using Shark.Fido2.Metadata.Core.Domain;

namespace Shark.Fido2.Metadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to retrieve cached metadata items.
/// </summary>
public interface IMetadataCachedService
{
    /// <summary>
    /// Gets a cached metadata payload item by AAGUID.
    /// </summary>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The cached metadata payload item or null if not found.</returns>
    Task<MetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken = default);
}
