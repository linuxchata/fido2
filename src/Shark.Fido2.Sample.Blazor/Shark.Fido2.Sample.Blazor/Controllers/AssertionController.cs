using System.Net.Mime;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;

namespace Shark.Fido2.Sample.Blazor.Controllers;

/// <summary>
/// Assertion (authentication).
/// </summary>
[Route("[controller]")]
[ApiController]
public class AssertionController(IAssertion assertion) : ControllerBase
{
    private const string SessionName = "WebAuthn.RequestOptions";

    /// <summary>
    /// Gets credential request options.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    [IgnoreAntiforgeryToken]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Options(
        ServerPublicKeyCredentialGetOptionsRequest request,
        CancellationToken cancellationToken)
    {
        var requestOptions = await assertion.BeginAuthentication(request.Map(), cancellationToken);

        HttpContext.Session.SetString(SessionName, JsonSerializer.Serialize(requestOptions));

        return Ok(requestOptions.Map());
    }

    /// <summary>
    /// Validates credential.
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
        ServerPublicKeyCredentialAssertion request,
        CancellationToken cancellationToken)
    {
        var requestOptionsString = HttpContext.Session.GetString(SessionName);
        if (string.IsNullOrWhiteSpace(requestOptionsString))
        {
            return BadRequest(ServerResponse.CreateFailed());
        }

        var requestOptions = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(requestOptionsString);

        var response = await assertion.CompleteAuthentication(request.Map(), requestOptions!, cancellationToken);

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
