using System.Net.Mime;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;
using Shark.Sample.Fido2.Swagger;
using Swashbuckle.AspNetCore.Filters;

namespace Shark.Sample.Fido2.Controllers;

/// <summary>
/// Attestation (registration).
/// </summary>
[Route("[controller]")]
[ApiController]
public class AttestationController(IAttestation attestation, ILogger<AttestationController> logger) : ControllerBase
{
    private readonly IAttestation _attestation = attestation;

    /// <summary>
    /// Gets credential creation options.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [SwaggerRequestExample(
        typeof(ServerPublicKeyCredentialCreationOptionsRequest),
        typeof(ServerPublicKeyCredentialCreationOptionsRequestExample))]
    public async Task<IActionResult> Options(
        ServerPublicKeyCredentialCreationOptionsRequest request,
        CancellationToken cancellationToken)
    {
        var creationOptions = await _attestation.GetOptions(request.Map(), cancellationToken);

        var response = creationOptions.Map();

        HttpContext.Session.SetString("CreationOptions", JsonSerializer.Serialize(creationOptions));

        return Ok(response);
    }

    /// <summary>
    /// Creates credential.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("result")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Result(
        ServerPublicKeyCredentialAttestation request,
        CancellationToken cancellationToken)
    {
        if (request == null || request.Response == null)
        {
            return Ok(ServerResponse.CreateFailed());
        }

        var creationOptionsString = HttpContext.Session.GetString("CreationOptions");

        var creationOptions = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(creationOptionsString!);

        var response = await _attestation.Complete(request.Map(), creationOptions!, cancellationToken);

        if (response.IsValid)
        {
            return Ok(ServerResponse.Create());
        }
        else
        {
            logger.LogWarning("{Message}", response.Message);
            return BadRequest(ServerResponse.CreateFailed(response.Message));
        }
    }
}