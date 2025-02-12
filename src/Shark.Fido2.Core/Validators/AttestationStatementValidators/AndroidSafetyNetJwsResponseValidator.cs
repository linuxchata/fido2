using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Gode sample from Google:
/// https://github.com/googlesamples/android-play-safetynet/tree/master/server/csharp
/// </summary>
internal sealed class AndroidSafetyNetJwsResponseValidator : IAndroidSafetyNetJwsResponseValidator
{
    private const string ApkPackageName = "com.google.android.gms";

    public bool Validate(JwsResponse jwsResponse, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(jwsResponse);
        ArgumentNullException.ThrowIfNull(certificate);

        // TODO: Skip result of the validation, since provided certificate is not valid.
        ValidateSignature(jwsResponse, certificate);

        // TODO: Skip result of the validation, since JWS response has expired.
        ValidateTimestamp(jwsResponse);

        if (!ValidatePackageName(jwsResponse))
        {
            return false;
        }

        return true;
    }

    internal bool ValidateSignature(JwsResponse jwsResponse, X509Certificate2 certificate)
    {
        // JwsResponse includes certificates, but the attestation certificate is passed separately to delegate
        // certificate extraction to another class for better separation of concerns.
        var securityKey = new X509SecurityKey(certificate);
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ValidateLifetime = true,
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

    internal bool ValidateTimestamp(JwsResponse jwsResponse)
    {
        if (!long.TryParse(jwsResponse.TimestampMs, NumberStyles.Integer, CultureInfo.InvariantCulture, out long unixTimestampMs))
        {
            return false;
        }

        var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(unixTimestampMs).UtcDateTime;
        if (timestamp > DateTime.UtcNow)
        {
            return false;
        }

        // TODO: Define other validation rules for timestamp

        return true;
    }

    internal bool ValidatePackageName(JwsResponse jwsResponse)
    {
        if (!string.Equals(jwsResponse.ApkPackageName, ApkPackageName, StringComparison.InvariantCultureIgnoreCase))
        {
            return false;
        }

        return true;
    }
}
