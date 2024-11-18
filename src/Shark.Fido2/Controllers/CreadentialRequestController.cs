using Microsoft.AspNetCore.Mvc;

namespace Shark.Fido2.Controllers;

[Route("[controller]")]
[ApiController]
public class CreadentialRequestController : ControllerBase
{
    [HttpPost("initialize")]
    public async Task<IActionResult> Initialize()
    {
        return Ok();
    }

    [HttpPost("complete")]
    public async Task<IActionResult> Complete()
    {
        return Ok();
    }
}