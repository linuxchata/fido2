using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions.Repositories;

public interface IHttpClientConformanceTestRepository
{
    Task<List<string>> GetMetadataBlobEndpoints(CancellationToken cancellationToken);
    Task<string> GetMetadataBlob(string endpoint, CancellationToken cancellationToken);
    Task<X509Certificate2> GetRootCertificate(CancellationToken cancellationToken);
}
