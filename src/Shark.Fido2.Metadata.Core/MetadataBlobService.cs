using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Configurations;

namespace Shark.Fido2.Metadata.Core;

internal sealed class MetadataBlobService : IMetadataBlobService
{
    private readonly Fido2MetadataServiceConfiguration _configuration;

    public MetadataBlobService(IOptions<Fido2MetadataServiceConfiguration> options)
    {
        _configuration = options.Value;
    }

    public JwtSecurityToken ReadToken(string metadataBlob)
    {
        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = _configuration.MaximumTokenSizeInBytes,
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
            MaximumTokenSizeInBytes = _configuration.MaximumTokenSizeInBytes,
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
