using Shark.Fido2.ConvenienceMetadata.Core.Domain;

namespace Shark.Fido2.ConvenienceMetadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to retrieve cached convenience metadata items.
/// </summary>
public interface IConvenienceMetadataCachedService
{
    /// <summary>
    /// Gets a convenience metadata for an authenticator by AAGUID.
    /// </summary>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The convenience metadata for an authenticator or null if not found.</returns>
    Task<ConvenienceMetadataPayloadItem?> Get(Guid aaguid, CancellationToken cancellationToken);
}
