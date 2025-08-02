using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Gode sample from Google:
/// https://github.com/googlesamples/android-play-safetynet/tree/master/server/csharp.
/// </summary>
internal sealed class AndroidSafetyNetJwsResponseValidator : IAndroidSafetyNetJwsResponseValidator
{
    private const string Prefix = "Android SafetyNet attestation statement JWS response";

    private const string ApkPackageName = "com.google.android.gms";

    private readonly TimeProvider _timeProvider;

    public AndroidSafetyNetJwsResponseValidator(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;
    }

    public ValidatorInternalResult PreValidate(JwsResponse jwsResponse)
    {
        if (jwsResponse.CtsProfileMatch == null)
        {
            return ValidatorInternalResult.Invalid($"{Prefix} ctsProfileMatch is not found");
        }

        if (jwsResponse.BasicIntegrity == null)
        {
            return ValidatorInternalResult.Invalid($"{Prefix} basicIntegrity is not found");
        }

        if (string.IsNullOrWhiteSpace(jwsResponse.ApkPackageName) ||
            string.IsNullOrWhiteSpace(jwsResponse.ApkCertificateDigestSha256) ||
            string.IsNullOrWhiteSpace(jwsResponse.ApkDigestSha256))
        {
            return ValidatorInternalResult.Invalid($"{Prefix} APK information is not found");
        }

        if (jwsResponse.Certificates == null || jwsResponse.Certificates.Count == 0)
        {
            return ValidatorInternalResult.Invalid($"{Prefix} certificates are not found");
        }

        return ValidatorInternalResult.Valid();
    }

    public ValidatorInternalResult Validate(JwsResponse jwsResponse, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(jwsResponse);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!IsSignatureValid(jwsResponse, certificate))
        {
            return ValidatorInternalResult.Invalid($"{Prefix} signature is not valid");
        }

        if (!IsTimestampValid(jwsResponse))
        {
            return ValidatorInternalResult.Invalid($"{Prefix} timestamp is not valid");
        }

        if (!IsPackageNameValid(jwsResponse))
        {
            return ValidatorInternalResult.Invalid($"{Prefix} package name is not valid");
        }

        return ValidatorInternalResult.Valid();
    }

    private bool IsTimestampValid(JwsResponse jwsResponse)
    {
        if (!long.TryParse(
            jwsResponse.TimestampMs,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out long unixTimestampMs))
        {
            return false;
        }

        var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(unixTimestampMs).UtcDateTime;
        var now = _timeProvider.GetUtcNow();
        if (timestamp > now || timestamp < now.AddSeconds(-60))
        {
            return false;
        }

        return true;
    }

    private static bool IsSignatureValid(JwsResponse jwsResponse, X509Certificate2 certificate)
    {
        // JwsResponse includes certificates, but the attestation certificate is passed separately to delegate
        // certificate extraction to another class for better separation of concerns.
        var securityKey = new X509SecurityKey(certificate);
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
        };

        try
        {
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(jwsResponse.RawToken, validationParameters, out SecurityToken validatedToken);
            if (validatedToken is not JwtSecurityToken)
            {
                return false;
            }
        }
        catch (Exception)
        {
            return false;
        }

        return true;
    }

    private static bool IsPackageNameValid(JwsResponse jwsResponse)
    {
        if (!string.Equals(jwsResponse.ApkPackageName, ApkPackageName, StringComparison.InvariantCultureIgnoreCase))
        {
            return false;
        }

        return true;
    }
}
