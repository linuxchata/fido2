using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Metadata.Core.Abstractions;

namespace Shark.Fido2.Metadata.Core;

public sealed class MetadataBlobService : IMetadataBlobService
{
    public JwtSecurityToken ReadToken(string metadataBlob)
    {
        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = 6 * 1024 * 1024, // Configuration
        };

        if (!handler.CanReadToken(metadataBlob))
        {
            throw new InvalidOperationException();
        }

        return handler.ReadJwtToken(metadataBlob);
    }

    public async Task<bool> ValidateToken(string metadataBlob, X509Certificate2 certificate)
    {
        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = 6 * 1024 * 1024, // Configuration
        };

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new X509SecurityKey(certificate),
        };

        try
        {
            var result = await handler.ValidateTokenAsync(metadataBlob, validationParameters);
            return result.IsValid;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
