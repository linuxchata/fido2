using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Configurations;

namespace Shark.Fido2.Metadata.Core;

internal sealed class MetadataBlobService : IMetadataBlobService
{
    private readonly MetadataServiceConfiguration _configuration;

    public MetadataBlobService(IOptions<MetadataServiceConfiguration> options)
    {
        _configuration = options.Value;
    }

    public JwtSecurityToken ReadToken(string metadataBlob)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(metadataBlob);

        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = _configuration.MaximumTokenSizeInBytes,
        };

        if (!handler.CanReadToken(metadataBlob))
        {
            throw new InvalidOperationException("String is not a well formed Json Web Token (JWT)");
        }

        return handler.ReadJwtToken(metadataBlob);
    }

    public async Task<bool> IsTokenValid(string metadataBlob, List<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(metadataBlob);
        ArgumentNullException.ThrowIfNull(certificates);

        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = _configuration.MaximumTokenSizeInBytes,
        };

        var issuerSigningKeys = GetIssuerSigningKeys(certificates);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = issuerSigningKeys,
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

    private static List<SecurityKey> GetIssuerSigningKeys(List<X509Certificate2> certificates)
    {
        // X509SecurityKey has issues extracting public keys from ECDsa certificates, so the public keys are
        // extracted manually

        var issuerSigningKeys = new List<SecurityKey>();
        foreach (var certificate in certificates)
        {
            var ecdsaPublicKey = certificate.GetECDsaPublicKey();
            var rsaPublicKey = certificate.GetRSAPublicKey();

            if (ecdsaPublicKey != null)
            {
                issuerSigningKeys.Add(new ECDsaSecurityKey(ecdsaPublicKey));
            }
            else if (rsaPublicKey != null)
            {
                issuerSigningKeys.Add(new RsaSecurityKey(rsaPublicKey));
            }
            else
            {
                throw new InvalidOperationException("Certificate does not have a supported public key");
            }
        }

        return issuerSigningKeys;
    }
}
