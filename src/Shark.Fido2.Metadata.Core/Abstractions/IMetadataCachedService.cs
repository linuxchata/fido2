using Shark.Fido2.Metadata.Core.Domain;

namespace Shark.Fido2.Metadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to retrieve cached metadata items.
/// </summary>
public interface IMetadataCachedService
{
    /// <summary>
    /// Gets a metadata for an authenticator by AAGUID.
    /// </summary>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The metadata for an authenticator or null if not found.</returns>
    Task<MetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken);
}
