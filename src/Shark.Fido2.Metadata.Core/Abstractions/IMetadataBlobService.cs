using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface IMetadataBlobService
{
    JwtSecurityToken ReadToken(string metadataBlob);
    Task<bool> ValidateToken(string metadataBlob, X509Certificate2 certificate);
}
