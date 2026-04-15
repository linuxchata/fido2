using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to retrieve metadata BLOB payloads.
/// </summary>
public interface IMetadataService
{
    /// <summary>
    /// Gets a metadata BLOB payload.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The metadata BLOB payload.</returns>
    Task<MetadataBlobPayload> Get(CancellationToken cancellationToken);
}
