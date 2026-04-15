using Shark.Fido2.ConvenienceMetadata.Core.Domain;

namespace Shark.Fido2.ConvenienceMetadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to retrieve cached convenience metadata items.
/// </summary>
public interface IConvenienceMetadataCachedService
{
    /// <summary>
    /// Gets a cached convenience metadata payload item by AAGUID.
    /// </summary>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The cached metadata payload item or null if not found.</returns>
    Task<ConvenienceMetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken);
}
