using Shark.Fido2.ConvenienceMetadata.Core.Models;

namespace Shark.Fido2.ConvenienceMetadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to retrieve the convenience metadata BLOB.
/// </summary>
public interface IConvenienceMetadataService
{
    /// <summary>
    /// Gets a convenience metadata BLOB payload.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The convenience metadata payload or null if unreachable.</returns>
    Task<ConvenienceMetadataPayload?> Get(CancellationToken cancellationToken);
}
