using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Metadata.Core.Abstractions;

namespace Shark.Fido2.Metadata.Server.Controllers;

[ApiController]
[Route("[controller]")]
public sealed class MetadataController(IMetadataService metadataService) : ControllerBase
{
    [HttpPost("refresh")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Refresh(CancellationToken cancellationToken)
    {
        await metadataService.Refresh(cancellationToken);

        return NoContent();
    }
}
