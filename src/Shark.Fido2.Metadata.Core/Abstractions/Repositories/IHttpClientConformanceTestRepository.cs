using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions.Repositories;

/// <summary>
/// The interface representing the logic to retrieve metadata for conformance testing.
/// </summary>
public interface IHttpClientConformanceTestRepository
{
    /// <summary>
    /// Gets metadata BLOB endpoints from a remote URL.
    /// </summary>
    /// <param name="remoteUrl">The remote URL.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A list of metadata BLOB endpoints.</returns>
    Task<List<string>> GetMetadataBlobEndpoints(string remoteUrl, CancellationToken cancellationToken);

    /// <summary>
    /// Gets a metadata BLOB from an endpoint.
    /// </summary>
    /// <param name="endpoint">The endpoint of a metadata BLOB.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The metadata BLOB content.</returns>
    Task<string> GetMetadataBlob(string endpoint, CancellationToken cancellationToken);

    /// <summary>
    /// Gets a root certificate from a URL.
    /// </summary>
    /// <param name="url">The URL of the root certificate.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The X509 root certificate.</returns>
    Task<X509Certificate2> GetRootCertificate(string url, CancellationToken cancellationToken);
}
