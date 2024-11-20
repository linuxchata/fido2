using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Constants;
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

        var response = new CredentialValidateResponse
        {
            Status = Status.Ok,
        };

        return Ok(response);
    }
}