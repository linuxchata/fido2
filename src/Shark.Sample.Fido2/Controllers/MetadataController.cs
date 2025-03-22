using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Metadata.Core.Abstractions;

namespace Shark.Sample.Fido2.Controllers;

/// <summary>
/// Metadata
/// </summary>
[ApiController]
[Route("[controller]")]
public sealed class MetadataController(IMetadataService metadataService) : ControllerBase
{
    /// <summary>
    /// Refreshes metadata.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("refresh")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Refresh(CancellationToken cancellationToken)
    {
        await metadataService.Refresh(cancellationToken);

        return NoContent();
    }
}
