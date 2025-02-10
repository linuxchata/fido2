using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Services;

internal sealed class JwsResponseParserService : IJwsResponseParserService
{
    private const string ClaimTypeNonce = "nonce";

    public JwsResponse? Parse(byte[] response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var jwsResponse = Encoding.UTF8.GetString(response);

        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(jwsResponse))
        {
            return null;
        }

        var jwtToken = handler.ReadJwtToken(jwsResponse);

        var certificates = new List<object>();
        if (jwtToken.Header.TryGetValue(AttestationStatement.Certificate, out var x5c) &&
            x5c is List<object>)
        {
            certificates.AddRange((List<object>)x5c);
        }

        var nonce = jwtToken.Claims?.FirstOrDefault(c => c.Type == ClaimTypeNonce);

        return new JwsResponse
        {
            Algorithm = jwtToken.Header?.Alg,
            Certificates = certificates,
            Nonce = nonce?.Value,
        };
    }
}
