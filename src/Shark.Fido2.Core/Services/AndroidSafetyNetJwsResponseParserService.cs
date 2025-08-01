﻿using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Services;

/// <summary>
/// Gode sample from Google:
/// https://github.com/googlesamples/android-play-safetynet/tree/master/server/csharp.
/// </summary>
internal sealed class AndroidSafetyNetJwsResponseParserService : IAndroidSafetyNetJwsResponseParserService
{
    private const string ClaimTypeNonce = "nonce";
    private const string ClaimTypeCtsProfileMatch = "ctsProfileMatch";
    private const string ClaimTypeBasicIntegrity = "basicIntegrity";
    private const string ClaimTypeApkPackageName = "apkPackageName";
    private const string ClaimTypeApkCertificateDigestSha256 = "apkCertificateDigestSha256";
    private const string ClaimTypeApkDigestSha256 = "apkDigestSha256";
    private const string ClaimTypeTimestampMs = "timestampMs";

    public JwsResponse? Parse(byte[] response)
    {
        ArgumentNullException.ThrowIfNull(response);

        // Response is the UTF-8 encoded result of the getJwsResult() call of the SafetyNet API.
        var jwsResponse = Encoding.UTF8.GetString(response);

        if (string.IsNullOrWhiteSpace(jwsResponse))
        {
            return null;
        }

        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(jwsResponse))
        {
            return null;
        }

        var jwtToken = handler.ReadJwtToken(jwsResponse);

        var certificates = new List<object>();
        if (jwtToken.Header.TryGetValue(AttestationStatement.Certificate, out var x5c) &&
            x5c is List<object> x5cList)
        {
            certificates.AddRange(x5cList);
        }

        var nonce = GetClaim(jwtToken.Claims, ClaimTypeNonce);
        var ctsProfileMatchClaim = GetClaim(jwtToken.Claims, ClaimTypeCtsProfileMatch);
        var basicIntegrityClaim = GetClaim(jwtToken.Claims, ClaimTypeBasicIntegrity);
        var apkPackageNameClaim = GetClaim(jwtToken.Claims, ClaimTypeApkPackageName);
        var apkCertificateDigestSha256Claim = GetClaim(jwtToken.Claims, ClaimTypeApkCertificateDigestSha256);
        var apkDigestSha256Claim = GetClaim(jwtToken.Claims, ClaimTypeApkDigestSha256);
        var timestampMsClaim = GetClaim(jwtToken.Claims, ClaimTypeTimestampMs);

        return new JwsResponse
        {
            RawToken = jwsResponse,
            Algorithm = jwtToken.Header?.Alg,
            Certificates = certificates,
            Nonce = nonce?.Value,
            CtsProfileMatch = ParseBoolOrNull(ctsProfileMatchClaim?.Value),
            BasicIntegrity = ParseBoolOrNull(basicIntegrityClaim?.Value),
            ApkPackageName = apkPackageNameClaim?.Value,
            ApkCertificateDigestSha256 = apkCertificateDigestSha256Claim?.Value,
            ApkDigestSha256 = apkDigestSha256Claim?.Value,
            TimestampMs = timestampMsClaim?.Value,
        };
    }

    private static Claim? GetClaim(IEnumerable<Claim>? claims, string type)
    {
        return claims?.FirstOrDefault(c => c.Type == type);
    }

    private static bool? ParseBoolOrNull(string? input)
    {
        if (bool.TryParse(input, out bool result))
        {
            return result;
        }

        return null;
    }
}
