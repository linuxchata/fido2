using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface IMetadataReaderService
{
    Task<MetadataBlobPayload> ValidateAndRead(
        string metadataBlob,
        X509Certificate2 rootCertificate,
        CancellationToken cancellationToken);
}
