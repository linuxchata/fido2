using System.Net.Mime;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;
using Shark.Fido2.Sample.Template.Services;

namespace Shark.Fido2.Sample.Template.Controllers;

[Route("[controller]")]
[ApiController]
public class AssertionController(IAssertion assertion, ICredentialService credentialService) : ControllerBase
{
    private const string SessionName = "WebAuthn.RequestOptions";

    [HttpPost("options")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<IActionResult> Options(
        ServerPublicKeyCredentialGetOptionsRequest request,
        CancellationToken cancellationToken)
    {
        if (request == null)
        {
            return BadRequest(ServerResponse.CreateFailed());
        }

        var requestOptions = await assertion.BeginAuthentication(request.Map(), cancellationToken);

        HttpContext.Session.SetString(SessionName, JsonSerializer.Serialize(requestOptions));

        return Ok(requestOptions.Map());
    }

    [HttpPost("result")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<IActionResult> Result(
        ServerPublicKeyCredentialAssertion request,
        CancellationToken cancellationToken)
    {
        if (request == null || request.Response == null)
        {
            return BadRequest(ServerResponse.CreateFailed());
        }

        var requestOptionsString = HttpContext.Session.GetString(SessionName);
        if (string.IsNullOrWhiteSpace(requestOptionsString))
        {
            return BadRequest(ServerResponse.CreateFailed());
        }

        var requestOptions = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(requestOptionsString!);

        var response = await assertion.CompleteAuthentication(request.Map(), requestOptions!, cancellationToken);

        HttpContext.Session.Remove(SessionName);

        if (response.IsValid)
        {
            var credential = await credentialService.Get(request.Id, cancellationToken);
            if (credential is null)
            {
                return NotFound();
            }

            return Ok(ServerResponse.Create());
        }
        else
        {
            return BadRequest(ServerResponse.CreateFailed(response.Message));
        }
    }
}
