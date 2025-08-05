using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to retrieve metadata blob payloads.
/// </summary>
public interface IMetadataService
{
    /// <summary>
    /// Gets a metadata blob payload.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The metadata blob payload.</returns>
    Task<MetadataBlobPayload> Get(CancellationToken cancellationToken);
}
