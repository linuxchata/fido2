using System.Net.Mime;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;
using Shark.Fido2.Sample.Filters;
using Shark.Fido2.Sample.Swagger;
using Swashbuckle.AspNetCore.Filters;

namespace Shark.Fido2.Sample.Controllers;

/// <summary>
/// Attestation (registration).
/// </summary>
[Route("[controller]")]
[ApiController]
[TypeFilter(typeof(RestApiExceptionFilter))]
public class AttestationController(IAttestation attestation, ILogger<AttestationController> logger) : ControllerBase
{
    private const string SessionName = "WebAuthn.CreateOptions";

    /// <summary>
    /// Gets credential create options.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    [IgnoreAntiforgeryToken]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [SwaggerRequestExample(
        typeof(ServerPublicKeyCredentialCreationOptionsRequest),
        typeof(ServerPublicKeyCredentialCreationOptionsRequestExample))]
    public async Task<IActionResult> Options(
        ServerPublicKeyCredentialCreationOptionsRequest request,
        CancellationToken cancellationToken)
    {
        var createOptions = await attestation.BeginRegistration(request.Map(), cancellationToken);

        HttpContext.Session.SetString(SessionName, JsonSerializer.Serialize(createOptions));

        return Ok(createOptions.Map());
    }

    /// <summary>
    /// Creates credential.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("result")]
    [IgnoreAntiforgeryToken]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Result(
        ServerPublicKeyCredentialAttestation request,
        CancellationToken cancellationToken)
    {
        var createOptionsString = HttpContext.Session.GetString(SessionName);
        if (string.IsNullOrWhiteSpace(createOptionsString))
        {
            return BadRequest(ServerResponse.CreateFailed());
        }

        logger.LogInformation("Create options: {CreateOptionsString}", createOptionsString);
        var createOptions = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(createOptionsString);

        logger.LogInformation("Attestation request: {Request}", JsonSerializer.Serialize(request.Map()));
        var response = await attestation.CompleteRegistration(request.Map(), createOptions!, cancellationToken);

        HttpContext.Session.Remove(SessionName);

        if (response.IsValid)
        {
            return Ok(ServerResponse.Create());
        }
        else
        {
            logger.LogError("{Message}", response.Message);
            return BadRequest(ServerResponse.CreateFailed(response.Message));
        }
    }
}
