using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions.Repositories;

/// <summary>
/// The interface representing the logic to retrieve metadata and certificates via HTTP.
/// </summary>
public interface IHttpClientRepository
{
    /// <summary>
    /// Gets a metadata blob.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The metadata blob content.</returns>
    Task<string> GetMetadataBlob(CancellationToken cancellationToken);

    /// <summary>
    /// Gets a root certificate.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The root certificate.</returns>
    Task<X509Certificate2> GetRootCertificate(CancellationToken cancellationToken);

    /// <summary>
    /// Gets certificates from a URL.
    /// </summary>
    /// <param name="url">The URL of certificates.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A list of certificates.</returns>
    Task<List<X509Certificate2>> GetCertificates(string url, CancellationToken cancellationToken);
}
