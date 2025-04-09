using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions.Repositories;

public interface IHttpClientConformanceTestRepository
{
    Task<List<string>> GetMetadataBlobEndpoints(string remoteUrl, CancellationToken cancellationToken);
    Task<string> GetMetadataBlob(string endpoint, CancellationToken cancellationToken);
    Task<X509Certificate2> GetRootCertificate(string url, CancellationToken cancellationToken);
}
