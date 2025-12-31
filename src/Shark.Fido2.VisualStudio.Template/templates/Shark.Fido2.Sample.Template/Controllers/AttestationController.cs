using System.Net.Mime;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Sample.Template.Controllers;

[Route("[controller]")]
[ApiController]
public class AttestationController(IAttestation attestation) : ControllerBase
{
    private const string SessionName = "WebAuthn.CreateOptions";

    [HttpPost("options")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<IActionResult> Options(
        ServerPublicKeyCredentialCreationOptionsRequest request,
        CancellationToken cancellationToken)
    {
        if (request == null)
        {
            return BadRequest(ServerResponse.CreateFailed());
        }

        var createOptions = await attestation.BeginRegistration(request.Map(), cancellationToken);

        HttpContext.Session.SetString(SessionName, JsonSerializer.Serialize(createOptions));

        return Ok(createOptions.Map());
    }

    [HttpPost("result")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
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

        var response = await attestation.CompleteRegistration(request.Map(), createOptions!, cancellationToken);

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
