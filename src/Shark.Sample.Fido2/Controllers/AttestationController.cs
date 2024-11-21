using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core;
using Shark.Fido2.Models;
using Shark.Fido2.Requests;
using Shark.Fido2.Responses;

namespace Shark.Fido2.Controllers;

/// <summary>
/// Registration
/// </summary>
[Route("[controller]")]
[ApiController]
public class AttestationController : ControllerBase
{
    /// <summary>
    /// Gets credential creation options
    /// </summary>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    public async Task<IActionResult> Options()
    {
        var challengeBytes = new byte[16];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(challengeBytes);

        var response = new CredentialGetOptionsResponse
        {
            Challenge = Convert.ToBase64String(challengeBytes),
            RelyingParty = new RelyingPartyResponse
            {
                Identifier = "localhost",
                Name = "Example CORP",
            },
            User = new UserResponse
            {
                Identifier = Guid.NewGuid().ToString(),
                Name = "johndoe@example.com",
                DisplayName = "John Doe",
            }
        };

        HttpContext.Session.SetString("Challenge", response.Challenge);

        return Ok(response);
    }

    /// <summary>
    /// Validate credential
    /// </summary>
    /// <param name="request"></param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("result")]
    public async Task<IActionResult> Result(ServerPublicKeyCredential request)
    {
        // The server will validate challenges, origins, signatures and the rest of
        // the ServerAuthenticatorAttestationResponse according to the algorithm
        // described in section 7.1 of the [Webauthn] specs, and will respond with
        // the appropriate ServerResponse message.

        var clientDataJsonArray = Convert.FromBase64String(request.Response.ClientDataJson);
        var decodedClientDataJson = Encoding.UTF8.GetString(clientDataJsonArray);

        var clientData = JsonSerializer.Deserialize<ClientDataModel>(decodedClientDataJson);

        var expectedChallenge = HttpContext.Session.GetString("Challenge");

        var response = new CredentialValidateResponse();

        var base64StringChallenge = Base64UrlToBase64(clientData?.Challenge!);

        if (!Compare(expectedChallenge!, base64StringChallenge))
        {
            response.Status = ResponseStatus.Failed;
        }
        else
        {
            response.Status = ResponseStatus.Ok;
        }

        return Ok(response);
    }

    private static string Base64UrlToBase64(string base64Url)
    {
        // Replace Base64URL characters with Base64 equivalents
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');

        // Add padding if necessary
        var padding = base64.Length % 4;
        if (padding > 0)
        {
            base64 += new string('=', 4 - padding);
        }

        return base64;
    }

    private bool Compare(string expected, string actual)
    {
        var expectedData = Convert.FromBase64String(expected);
        var actualData = Convert.FromBase64String(actual);

        if (expectedData.Length != actualData.Length)
        {
            return false;
        }

        for (var i = 0; i < expectedData.Length; i++)
        {
            if (expectedData[i] != actualData[i])
            {
                return false;
            }
        }

        return true;
    }
}