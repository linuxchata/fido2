using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Comparers;
using Shark.Fido2.Metadata.Core.Configurations;
using Shark.Fido2.Metadata.Core.Constants;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Services;

internal sealed class MetadataReaderService : IMetadataReaderService
{
    private const string NextUpdateDateTimeFormat = "yyyy-MM-dd";

    private readonly IHttpClientRepository _httpClientRepository;
    private readonly ICertificateValidator _certificateValidator;
    private readonly MetadataServiceConfiguration _configuration;
    private readonly ILogger<MetadataReaderService> _logger;

    public MetadataReaderService(
        IHttpClientRepository httpClientRepository,
        ICertificateValidator certificateValidator,
        IOptions<MetadataServiceConfiguration> options,
        ILogger<MetadataReaderService> logger)
    {
        _httpClientRepository = httpClientRepository;
        _certificateValidator = certificateValidator;
        _configuration = options.Value;
        _logger = logger;
    }

    public async Task<MetadataBlobPayload> ValidateAndRead(
        string metadataBlob,
        X509Certificate2 rootCertificate,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(metadataBlob);
        ArgumentNullException.ThrowIfNull(rootCertificate);

        var metadataBlobToken = ReadBlob(metadataBlob);

        _logger.LogDebug("Metadata BLOB is read");

        // Step 4
        // If the x5u attribute is present in the JWT Header, then:
        List<X509Certificate2> certificates;
        var certificateUrl = GetCertificateUrlFromToken(metadataBlobToken);
        if (!string.IsNullOrWhiteSpace(certificateUrl))
        {
            // The FIDO Server MUST verify that the URL specified by the x5u attribute has the same web-origin
            // as the URL used to download the metadata BLOB from. The FIDO Server SHOULD ignore the file if
            // the web-origin differs (in order to prevent loading objects from arbitrary sites).
            var areTheSameOrigins = UrlOriginComparer.CompareOrigins(
                certificateUrl,
                _configuration.MetadataBlobLocation);

            if (!areTheSameOrigins)
            {
                throw new InvalidDataException(
                    "X.509 URL is from different web-origin than metadata BLOB object");
            }

            // The FIDO Server MUST download the certificate (chain) from the URL specified by the x5u attribute
            // [JWS]. The certificate chain MUST be verified to properly chain to the metadata BLOB signing trust
            // anchor according to [RFC5280]. All certificates in the chain MUST be checked for revocation
            // according to [RFC5280].
            certificates = await _httpClientRepository.GetCertificates(certificateUrl, cancellationToken);

            if (certificates.Count != 0)
            {
                throw new InvalidDataException("X.509 URL does not have the certificate (chain)");
            }

            // The FIDO Server SHOULD ignore the file if the chain cannot be verified or if one of the chain
            // certificates is revoked.
            _certificateValidator.ValidateX509Chain(rootCertificate, certificates);
        }
        else
        {
            // Step 5
            // If the x5u attribute is missing, the chain should be retrieved from the x5c attribute. If that
            // attribute is missing as well, Metadata BLOB signing trust anchor is considered the BLOB signing
            // certificate chain.
            certificates = GetCertificatesFromToken(metadataBlobToken);
            if (certificates.Count != 0)
            {
                _certificateValidator.ValidateX509Chain(rootCertificate, certificates);
            }
            else
            {
                certificates.Add(rootCertificate);
            }
        }

        _logger.LogDebug("Metadata BLOB signing certificate chain is valid");

        // Step 6
        // Verify the signature of the Metadata BLOB object using the BLOB signing certificate chain (as determined
        // by the steps above). The FIDO Server SHOULD ignore the file if the signature is invalid.
        if (!await IsBlobValid(metadataBlob, certificates))
        {
            throw new InvalidDataException("Signature of the Metadata BLOB object is invalid");
        }

        _logger.LogDebug("Metadata BLOB signature is valid");

        // Step 6
        // It SHOULD also ignore the file if its number (no) is less or equal to the number of the last Metadata BLOB
        // object cached locally.
        // Skipped for now, as an expiring distributed cache is used.
        if (!metadataBlobToken.Payload.TryGetValue(MetadataBlobConstants.PayloadPropertyNumber, out var number) ||
            number is not int)
        {
            throw new InvalidDataException("Metadata token payload does not contain the 'no' property");
        }

        if (!metadataBlobToken.Payload.TryGetValue(MetadataBlobConstants.PayloadPropertyNextUpdate, out var nextUpdateString) ||
            nextUpdateString is not string)
        {
            throw new InvalidDataException("Metadata token payload does not contain the 'nextUpdate' property");
        }

        if (!DateTime.TryParseExact(
            (string)nextUpdateString,
            NextUpdateDateTimeFormat,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal,
            out DateTime nextUpdate))
        {
            throw new InvalidDataException("Metadata token payload 'nextUpdate' property is not date");
        }

        _logger.LogDebug("Metadata BLOB payload 'no' and 'nextUpdate' properties are valid");

        // Step 7
        // Write the verified object to a local cache as required.
        var payload = new List<MetadataBlobPayloadEntry>(metadataBlobToken.Claims.Count());
        metadataBlobToken.Claims.ToList().ForEach(claim =>
        {
            if (string.Equals(claim.Type, MetadataBlobConstants.ClientTypeEntries, StringComparison.OrdinalIgnoreCase))
            {
                var payloadEntry = JsonSerializer.Deserialize<MetadataBlobPayloadEntry>(claim.Value);
                if (payloadEntry != null)
                {
                    payload.Add(payloadEntry);
                }
            }
        });

        var metadataBlobPayload = new MetadataBlobPayload
        {
            Payload = payload,
            Number = (int)number,
            NextUpdate = nextUpdate.ToUniversalTime(),
        };

        _logger.LogDebug("Metadata BLOB payload is read");

        return metadataBlobPayload;
    }

    private JwtSecurityToken ReadBlob(string metadataBlob)
    {
        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = _configuration.MaximumTokenSizeInBytes,
        };

        try
        {
            return handler.ReadJwtToken(metadataBlob);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Failed to parse Json Web Token (JWT) from FIDO Metadata Service: {ex.Message}");
        }
    }

    private async Task<bool> IsBlobValid(string metadataBlob, List<X509Certificate2> certificates)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(metadataBlob);
        ArgumentNullException.ThrowIfNull(certificates);

        var handler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = _configuration.MaximumTokenSizeInBytes,
        };

        var issuerSigningKeys = GetIssuerSigningKeys(certificates);

        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = issuerSigningKeys.Select(a => a.SecurityKey),
            };

            var result = await handler.ValidateTokenAsync(metadataBlob, validationParameters);
            return result.IsValid;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            issuerSigningKeys.ForEach(a => a.Disposable.Dispose());
            certificates.ForEach(c => c.Dispose());
        }
    }

    private static List<(SecurityKey SecurityKey, IDisposable Disposable)> GetIssuerSigningKeys(
        List<X509Certificate2> certificates)
    {
        // X509SecurityKey has issues extracting public keys from ECDsa certificates, so they are extracted manually
        var issuerSigningKeys = new List<(SecurityKey, IDisposable)>(certificates.Count);
        foreach (var certificate in certificates)
        {
            var ecdsaPublicKey = certificate.GetECDsaPublicKey();
            var rsaPublicKey = certificate.GetRSAPublicKey();

            if (ecdsaPublicKey != null)
            {
                issuerSigningKeys.Add((new ECDsaSecurityKey(ecdsaPublicKey), ecdsaPublicKey));
            }
            else if (rsaPublicKey != null)
            {
                issuerSigningKeys.Add((new RsaSecurityKey(rsaPublicKey), rsaPublicKey));
            }
            else
            {
                throw new InvalidOperationException("Certificate does not have a supported public key");
            }
        }

        return issuerSigningKeys;
    }

    private static string? GetCertificateUrlFromToken(JwtSecurityToken metadataToken)
    {
        if (!metadataToken.Header.TryGetValue(MetadataBlobConstants.HeaderX5u, out var x5u) || x5u is not string)
        {
            return null;
        }

        if (x5u is not string x5uValue)
        {
            throw new InvalidDataException("JWT header 'x5u' attribute is not a string");
        }

        return x5uValue;
    }

    private static List<X509Certificate2> GetCertificatesFromToken(JwtSecurityToken metadataToken)
    {
        if (!metadataToken.Header.TryGetValue(MetadataBlobConstants.HeaderX5c, out var x5c) || x5c is not List<object>)
        {
            throw new InvalidDataException("JWT header does not contain a valid 'x5c' attribute");
        }

        if (x5c is not List<object> x5cValue)
        {
            throw new InvalidDataException("JWT header 'x5c' attribute is not a list of objects");
        }

        var certificates = new List<X509Certificate2>(x5cValue.Count);

        foreach (var certificate in x5cValue)
        {
            var certificateString = certificate?.ToString();
            if (!string.IsNullOrWhiteSpace(certificateString))
            {
                var x509Certificate = new X509Certificate2(Convert.FromBase64String(certificateString));
                certificates.Add(x509Certificate);
            }
        }

        return certificates;
    }
}
