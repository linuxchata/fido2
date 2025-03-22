using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Comparers;
using Shark.Fido2.Metadata.Core.Configurations;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core;

public sealed class MetadataService : IMetadataService
{
    private readonly IHttpClientRepository _httpClientRepository;
    private readonly IMetadataBlobService _metadataBlobService;
    private readonly ICertificateValidator _certificateValidator;
    private readonly MetadataServiceConfiguration _configuration;

    public MetadataService(
        IHttpClientRepository httpClientRepository,
        IMetadataBlobService metadataBlobService,
        ICertificateValidator certificateValidator,
        IOptions<MetadataServiceConfiguration> options)
    {
        _httpClientRepository = httpClientRepository;
        _metadataBlobService = metadataBlobService;
        _certificateValidator = certificateValidator;
        _configuration = options.Value;
    }

    public async Task Refresh(CancellationToken cancellationToken)
    {
        // Step 1
        // Download and cache the root signing trust anchor from the respective MDS root location e.g.
        // More information can be found at https://fidoalliance.org/metadata/
        var rootCertificate = await _httpClientRepository.GetRootCertificate(cancellationToken);

        // Step 3
        // The FIDO Server MUST be able to download the latest metadata BLOB object from the well-known URL when
        // appropriate, e.g. https://mds.fidoalliance.org/. The nextUpdate field of the Metadata BLOB specifies a
        // date when the download SHOULD occur at latest.
        var metadataBlob = await _httpClientRepository.GetMetadataBlob(cancellationToken);

        var metadataToken = _metadataBlobService.ReadToken(metadataBlob);

        X509Certificate2 leafCertificate = null!;

        // Step 4
        // If the x5u attribute is present in the JWT Header, then:
        var certificateUrl = GetCertificateUrlFromToken(metadataToken);
        if (!string.IsNullOrWhiteSpace(certificateUrl))
        {
            // The FIDO Server MUST verify that the URL specified by the x5u attribute has the same web-origin
            // as the URL used to download the metadata BLOB from. The FIDO Server SHOULD ignore the file if
            // the web-origin differs (in order to prevent loading objects from arbitrary sites).
            var areTheSameOrigins = UrlOriginComparer.CompareOrigins(
                certificateUrl,
                _configuration.MetadataBlobLocationUrl);

            if (!areTheSameOrigins)
            {
                throw new InvalidDataException(
                    "X.509 URL is from different web-origin than metadata BLOB object");
            }

            // The FIDO Server MUST download the certificate (chain) from the URL specified by the x5u attribute
            // [JWS]. The certificate chain MUST be verified to properly chain to the metadata BLOB signing trust
            // anchor according to [RFC5280]. All certificates in the chain MUST be checked for revocation
            // according to [RFC5280].
            var certificates = await _httpClientRepository.GetCertificates(certificateUrl, cancellationToken);

            if (certificates.Count != 0)
            {
                throw new InvalidDataException(
                    "X.509 URL does not have the certificate (chain)");
            }

            // The FIDO Server SHOULD ignore the file if the chain cannot be verified or if one of the chain
            // certificates is revoked.
            leafCertificate = certificates.First();
            _certificateValidator.ValidateX509Chain(rootCertificate, leafCertificate, certificates);
        }
        else
        {
            // Step 5
            // If the x5u attribute is missing, the chain should be retrieved from the x5c attribute. If that
            // attribute is missing as well, Metadata BLOB signing trust anchor is considered the BLOB signing
            // certificate chain.
            var certificates = GetCertificatesFromToken(metadataToken);
            if (certificates.Count != 0)
            {
                leafCertificate = certificates.First();
                _certificateValidator.ValidateX509Chain(rootCertificate, leafCertificate, certificates);
            }
            else
            {
                leafCertificate = rootCertificate;
            }
        }

        // Step 6
        // Verify the signature of the Metadata BLOB object using the BLOB signing certificate chain (as determined
        // by the steps above). The FIDO Server SHOULD ignore the file if the signature is invalid.
        await _metadataBlobService.ValidateToken(metadataBlob, leafCertificate);

        // Step 6
        // It SHOULD also ignore the file if its number (no) is less or equal to the number of the last Metadata BLOB
        // object cached locally.
        // TODO: Implement this step
        if (!metadataToken.Payload.TryGetValue(Constants.PayloadPropertyNumber, out var number))
        {
            throw new InvalidDataException("Metadata token payload does not contain the 'no' property");
        }

        // Step 7
        // Write the verified object to a local cache as required.
        var result = new List<MetadataBlobPayloadEntry>(metadataToken.Claims.Count());
        metadataToken.Claims.ToList().ForEach(claim =>
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

    private static string? GetCertificateUrlFromToken(JwtSecurityToken metadataToken)
    {
        if (!metadataToken.Header.TryGetValue(Constants.HeaderX5u, out var x5u) || x5u is not string)
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
        if (!metadataToken.Header.TryGetValue(Constants.HeaderX5c, out var x5c) || x5c is not List<object>)
        {
            throw new InvalidDataException("JWT header does not contain a valid 'x5c' attribute");
        }

        if (x5c is not List<object> x5cValue)
        {
            throw new InvalidDataException("JWT header 'x5c' attribute is not a list of objects");
        }

        return x5cValue.Select(c => new X509Certificate2(Convert.FromBase64String(c.ToString()!))).ToList();
    }
}
