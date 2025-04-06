using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;

namespace Shark.Portal.Fido2.Controllers;

/// <summary>
/// Attestation (registration).
/// </summary>
[Route("[controller]")]
[ApiController]
public class AttestationController(IAttestation attestation) : ControllerBase
{
    private readonly IAttestation _attestation = attestation;

    /// <summary>
    /// Gets credential creation options.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    public async Task<IActionResult> Options(ServerPublicKeyCredentialCreationOptionsRequest request)
    {
        var creationOptions = await _attestation.GetOptions(request.Map());

        var response = creationOptions.Map();

        HttpContext.Session.SetString("CreationOptions", JsonSerializer.Serialize(creationOptions));

        return Ok(response);
    }

    /// <summary>
    /// Creates credential.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("result")]
    public async Task<IActionResult> Result(ServerPublicKeyCredentialAttestation request)
    {
        if (request == null || request.Response == null)
        {
            return Ok(ServerResponse.CreateFailed());
        }

        var creationOptionsString = HttpContext.Session.GetString("CreationOptions");

        var creationOptions = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(creationOptionsString!);

        var response = await _attestation.Complete(request.Map(), creationOptions!);

        if (response.IsValid)
        {
            return Ok(ServerResponse.Create());
        }
        else
        {
            return BadRequest(ServerResponse.CreateFailed(response.Message));
        }
    }
}