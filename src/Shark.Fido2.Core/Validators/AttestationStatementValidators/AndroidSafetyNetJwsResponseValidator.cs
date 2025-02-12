using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

internal sealed class AndroidSafetyNetJwsResponseValidator : IAndroidSafetyNetJwsResponseValidator
{
    public bool Validate(JwsResponse jwsResponse, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(jwsResponse);

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
}
