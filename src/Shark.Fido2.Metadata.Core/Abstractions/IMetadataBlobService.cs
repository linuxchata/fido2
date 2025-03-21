using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface IMetadataBlobService
{
    JwtSecurityToken Read(string metadataBlob);
    Task<bool> Validate(string metadataBlob, X509Certificate2 certificate);
}
