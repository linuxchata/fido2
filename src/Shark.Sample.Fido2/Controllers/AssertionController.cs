using System.Net.Mime;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;
using Shark.Sample.Fido2.Swagger;
using Swashbuckle.AspNetCore.Filters;

namespace Shark.Sample.Fido2.Controllers;

/// <summary>
/// Assertion (authentication)
/// </summary>
[Route("[controller]")]
[ApiController]
public class AssertionController(IAssertion assertion) : ControllerBase
{
    private readonly IAssertion _assertion = assertion;

    /// <summary>
    /// Gets credential request options.
    /// </summary>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [SwaggerRequestExample(
        typeof(ServerPublicKeyCredentialGetOptionsRequest),
        typeof(ServerPublicKeyCredentialGetOptionsRequestExample))]
    public async Task<IActionResult> Options(ServerPublicKeyCredentialGetOptionsRequest request)
    {
        var requestOptions = await _assertion.RequestOptions(request.Map());

        var response = requestOptions.Map();

        HttpContext.Session.SetString("RequestOptions", JsonSerializer.Serialize(requestOptions));

        return Ok(response);
    }

    /// <summary>
    /// Validate credential.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("result")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Result(ServerPublicKeyCredentialAssertion request)
    {
        if (request == null)
        {
            return Ok(ServerResponse.CreateFailed());
        }

        var requestOptionsString = HttpContext.Session.GetString("RequestOptions");

        var requestOptions = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(requestOptionsString!);

        var response = await _assertion.Complete(request.Map(), requestOptions!);

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