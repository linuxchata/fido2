using Microsoft.AspNetCore.Mvc;

namespace Shark.Sample.Fido2.Controllers;

[Route("[controller]")]
[ApiController]
public class AssertionController : ControllerBase
{
    [HttpPost("initialize")]
    public IActionResult Initialize()
    {
        return Ok();
    }

    [HttpPost("complete")]
    public IActionResult Complete()
    {
        return Ok();
    }
}