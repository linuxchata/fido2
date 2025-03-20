using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core;

public sealed class MetadataService : IMetadataService
{
    private readonly IHttpClientRepository _httpClientRepository;
    private readonly ICertificateValidator _certificateValidator;

    public MetadataService(
        IHttpClientRepository httpClientRepository,
        ICertificateValidator certificateValidator)
    {
        _httpClientRepository = httpClientRepository;
        _certificateValidator = certificateValidator;
    }

    public async Task Refresh()
    {
        // Step 3
        // The FIDO Server MUST be able to download the latest metadata BLOB object from the well-known URL when
        // appropriate, e.g. https://mds.fidoalliance.org/. The nextUpdate field of the Metadata BLOB specifies a
        // date when the download SHOULD occur at latest.
        var metadataBlob = await _httpClientRepository.GetMetadataBlob();

        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = 6 * 1024 * 1024, // Configuration
        };

        if (!handler.CanReadToken(metadataBlob))
        {
            throw new InvalidOperationException();
        }

        var jwtToken = handler.ReadJwtToken(metadataBlob);

        // Step 5
        // If the x5u attribute is missing, the chain should be retrieved from the x5c attribute. If that attribute
        // is missing as well, Metadata BLOB signing trust anchor is considered the BLOB signing certificate chain.
        if (!jwtToken.Header.TryGetValue(Constants.HeaderX5c, out var x5c) || x5c is not List<object>)
        {
            throw new InvalidOperationException();
        }

        if (x5c is not List<object> x5cList)
        {
            throw new InvalidOperationException();
        }

        var rootCertificate = await _httpClientRepository.GetRootCertificate();
        var certificates = x5cList.Select(a => a.ToString()!).ToList();
        var leafCertificate = new X509Certificate2(Convert.FromBase64String(certificates.FirstOrDefault()!));
        _certificateValidator.ValidateX509Chain(rootCertificate, leafCertificate, certificates);

        // Step 6
        // Verify the signature of the Metadata BLOB object using the BLOB signing certificate chain (as determined
        // by the steps above). The FIDO Server SHOULD ignore the file if the signature is invalid.
        await ValidateBlob(handler, leafCertificate, metadataBlob);

        // Step 6
        // It SHOULD also ignore the file if its number (no) is less or equal to the number of the last Metadata BLOB
        // object cached locally.
        // TODO: Implement this step
        if (!jwtToken.Payload.TryGetValue(Constants.PayloadPropertyNumber, out var number))
        {
            throw new InvalidOperationException();
        }

        // Step 7
        // Write the verified object to a local cache as required.
        var result = new List<MetadataBlobPayloadEntry>(jwtToken.Claims.Count());
        jwtToken.Claims.ToList().ForEach(claim =>
        {
            if (string.Equals(claim.Type, Constants.ClientTypeEntries, StringComparison.OrdinalIgnoreCase))
            {
                var payloadEntry = JsonSerializer.Deserialize<MetadataBlobPayloadEntry>(claim.Value);
                if (payloadEntry != null)
                {
                    result.Add(payloadEntry);
                }
            }
        });
    }

    private async Task<bool> ValidateBlob(
        JwtSecurityTokenHandler handler,
        X509Certificate2 certificate,
        string metadataBlob)
    {
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
