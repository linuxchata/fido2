using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
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
    /// Gets Credential Creation Options
    /// </summary>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    public async Task<IActionResult> Options()
    {
        var challengeBytes = new byte[16];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(challengeBytes);

        var response = new CreadentialCreateInitializeResponse
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
    /// Complete registration
    /// </summary>
    /// <returns>The HTTP response.</returns>
    [HttpPost("complete")]
    public async Task<IActionResult> Complete()
    {
        return Ok();
    }
}