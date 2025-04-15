﻿using System.Net.Mime;
using System.Text.Json;
using System.Threading;
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
/// Assertion (authentication).
/// </summary>
[Route("[controller]")]
[ApiController]
public class AssertionController(IAssertion assertion, ILogger<AssertionController> logger) : ControllerBase
{
    private readonly IAssertion _assertion = assertion;

    /// <summary>
    /// Gets credential request options.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [SwaggerRequestExample(
        typeof(ServerPublicKeyCredentialGetOptionsRequest),
        typeof(ServerPublicKeyCredentialGetOptionsRequestExample))]
    public async Task<IActionResult> Options(
        ServerPublicKeyCredentialGetOptionsRequest request,
        CancellationToken cancellationToken)
    {
        var requestOptions = await _assertion.RequestOptions(request.Map(), cancellationToken);

        var response = requestOptions.Map();

        HttpContext.Session.SetString("RequestOptions", JsonSerializer.Serialize(requestOptions));

        return Ok(response);
    }

    /// <summary>
    /// Validates credential.
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
        ServerPublicKeyCredentialAssertion request,
        CancellationToken cancellationToken)
    {
        if (request == null)
        {
            return Ok(ServerResponse.CreateFailed());
        }

        var requestOptionsString = HttpContext.Session.GetString("RequestOptions");

        var requestOptions = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(requestOptionsString!);

        var response = await _assertion.Complete(request.Map(), requestOptions!, cancellationToken);

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