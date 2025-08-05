using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to validate and read metadata blobs.
/// </summary>
public interface IMetadataReaderService
{
    /// <summary>
    /// Validates and reads a metadata blob.
    /// </summary>
    /// <param name="metadataBlob">The metadata blob.</param>
    /// <param name="rootCertificate">The root certificate.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The validated metadata blob payload.</returns>
    Task<MetadataBlobPayload> ValidateAndRead(
        string metadataBlob,
        X509Certificate2 rootCertificate,
        CancellationToken cancellationToken);
}
