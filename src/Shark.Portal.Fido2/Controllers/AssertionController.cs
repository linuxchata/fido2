﻿using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;

namespace Shark.Portal.Fido2.Controllers;

/// <summary>
/// Assertion (authentication).
/// </summary>
[Route("[controller]")]
[ApiController]
public class AssertionController(IAssertion assertion) : ControllerBase
{
    private readonly IAssertion _assertion = assertion;

    /// <summary>
    /// Gets credential request options.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    public async Task<IActionResult> Options(ServerPublicKeyCredentialGetOptionsRequest request)
    {
        var requestOptions = await _assertion.RequestOptions(request.Map());

        var response = requestOptions.Map();

        HttpContext.Session.SetString("RequestOptions", JsonSerializer.Serialize(requestOptions));

        return Ok(response);
    }

    /// <summary>
    /// Validates credential.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("result")]
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