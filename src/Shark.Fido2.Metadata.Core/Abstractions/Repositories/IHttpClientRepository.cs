using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions.Repositories;

public interface IHttpClientRepository
{
    Task<string> GetMetadataBlob(CancellationToken cancellationToken);
    Task<X509Certificate2> GetRootCertificate(CancellationToken cancellationToken);
    Task<List<X509Certificate2>> GetCertificates(string url, CancellationToken cancellationToken);
}
