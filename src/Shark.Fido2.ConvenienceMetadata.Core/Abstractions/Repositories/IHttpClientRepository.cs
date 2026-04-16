namespace Shark.Fido2.ConvenienceMetadata.Core.Abstractions.Repositories;

/// <summary>
/// The interface representing the logic to retrieve convenience metadata via HTTP.
/// </summary>
public interface IHttpClientRepository
{
    /// <summary>
    /// Gets a convenience metadata BLOB.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The metadata BLOB content.</returns>
    Task<string> GetConvenienceMetadataBlob(CancellationToken cancellationToken);
}
