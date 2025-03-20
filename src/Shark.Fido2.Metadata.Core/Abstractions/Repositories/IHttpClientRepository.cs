using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions.Repositories;

public interface IHttpClientRepository
{
    Task<string> GetMetadataBlob();
    Task<X509Certificate2?> GetRootCertificate();
}
