using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace Shark.Fido2.Controllers;

[Route("[controller]")]
[ApiController]
public class CreadentialCreateController : ControllerBase
{
    /// <summary>
    /// Initialize registration
    /// </summary>
    /// <returns>The HTTP response.</returns>
    [HttpPost("initialize")]
    public async Task<IActionResult> Initialize()
    {
        var challengeBytes = new byte[16];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(challengeBytes);

        return Ok(Convert.ToBase64String(challengeBytes));
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