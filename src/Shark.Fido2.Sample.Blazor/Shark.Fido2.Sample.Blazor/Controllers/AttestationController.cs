using System.Net.Mime;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Sample.Blazor.Controllers;

/// <summary>
/// Attestation (registration).
/// </summary>
[Route("[controller]")]
[ApiController]
public class AttestationController(IAttestation attestation) : ControllerBase
{
    private const string SessionName = "WebAuthn.CreateOptions";

    private readonly IAttestation _attestation = attestation;

    /// <summary>
    /// Gets credential create options.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Options(
        ServerPublicKeyCredentialCreationOptionsRequest request,
        CancellationToken cancellationToken)
    {
        if (request == null)
        {
            return BadRequest(ServerResponse.CreateFailed());
        }

        var createOptions = await _attestation.BeginRegistration(request.Map(), cancellationToken);

        var response = createOptions.Map();

        HttpContext.Session.SetString(SessionName, JsonSerializer.Serialize(createOptions));

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
            return BadRequest(ServerResponse.CreateFailed());
        }

        var createOptionsString = HttpContext.Session.GetString(SessionName);

        if (string.IsNullOrWhiteSpace(createOptionsString))
        {
            return BadRequest(ServerResponse.CreateFailed());
        }

        var createOptions = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(createOptionsString!);

        var response = await _attestation.CompleteRegistration(request.Map(), createOptions!, cancellationToken);

        HttpContext.Session.Remove(SessionName);

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