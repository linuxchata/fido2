using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Shark.Fido2.Metadata.Core.Abstractions;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Shark.Fido2.Metadata.Core;

public sealed class MetadataService : IMetadataService
{
    public async Task Refresh()
    {
        using var client = new HttpClient();
        using var stream = await client.GetStreamAsync("https://mds3.fidoalliance.org/");
        using var reader = new StreamReader(stream);
        var blob = reader.ReadToEnd();

        var handler = new JwtSecurityTokenHandler();
        handler.MaximumTokenSizeInBytes = 6 * 1024 * 1024;
        if (!handler.CanReadToken(blob))
        {
        }

        await ValidateAccessToken(handler, blob);

        var jwtToken = handler.ReadJwtToken(blob);

        var dataToSign = jwtToken.EncodedHeader + "." + jwtToken.EncodedPayload;
        var dataBytes = Encoding.UTF8.GetBytes(dataToSign);

        jwtToken.Header.TryGetValue("alg", out var alg);

    }

    private async Task<bool> ValidateAccessToken(JwtSecurityTokenHandler handler, string blob)
    {
        var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Certificates", "GlobalSignRootCAR3.pem");
        var pem = File.ReadAllText(path);
        var certificate = new X509Certificate2(ConvertPemToDer(pem));
        if (certificate == null)
        {
            throw new Exception("Failed to load certificate.");
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            //IssuerSigningKey = new X509SecurityKey(certificate),
            IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
            {
                // Ignore `kid` and always return a known key
                return [new X509SecurityKey(certificate)];
            },
        };

        try
        {
            var result = await handler.ValidateTokenAsync(blob, validationParameters);
        }
        catch (Exception ex)
        {
            var td = ex.Message;
            return false;
        }

        return true;
    }

    static byte[] ConvertPemToDer(string pem)
    {
        string base64 = pem.Replace("-----BEGIN CERTIFICATE-----", "")
                           .Replace("-----END CERTIFICATE-----", "")
                           .Replace("\n", "")
                           .Replace("\r", "");
        return Convert.FromBase64String(base64);
    }
}
