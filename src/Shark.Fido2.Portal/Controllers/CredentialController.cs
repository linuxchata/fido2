using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Portal.Services;

namespace Shark.Fido2.Portal.Controllers;

/// <summary>
/// Credential
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class CredentialController : ControllerBase
{
    private readonly ICredentialService _credentialService;

    public CredentialController(ICredentialService credentialService)
    {
        _credentialService = credentialService;
    }

    /// <summary>
    /// Gets credential.
    /// </summary>
    /// <param name="id">The credential identifier.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpGet]
    public async Task<IActionResult> Get(string id, CancellationToken cancellationToken)
    {
        var credential = await _credentialService.Get(id.FromBase64Url(), cancellationToken);

        return Ok(credential);
    }
}
