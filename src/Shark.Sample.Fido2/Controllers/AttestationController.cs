﻿using System.Net.Mime;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;
using Shark.Fido2.Models.Responses;
using Shark.Sample.Fido2.Swagger;
using Swashbuckle.AspNetCore.Filters;

namespace Shark.Sample.Fido2.Controllers;

/// <summary>
/// Attestation (registration)
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
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [SwaggerRequestExample(
        typeof(ServerPublicKeyCredentialCreationOptionsRequest),
        typeof(ServerPublicKeyCredentialCreationOptionsRequestExample))]
    public IActionResult Options(ServerPublicKeyCredentialCreationOptionsRequest request)
    {
        var credentialOptions = _attestation.GetOptions(request.Map());

        var response = credentialOptions.Map();

        HttpContext.Session.SetString("Challenge", response.Challenge);

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
    public async Task<IActionResult> Result(ServerPublicKeyCredential<ServerAuthenticatorAttestationResponse> request)
    {
        if (request == null)
        {
            return Ok(ServerResponse.CreateFailed());
        }

        // The server will validate challenges, origins, signatures and the rest of
        // the ServerAuthenticatorAttestationResponse according to the algorithm
        // described in section 7.1 of the [Webauthn] specs, and will respond with
        // the appropriate ServerResponse message.

        var expectedChallenge = HttpContext.Session.GetString("Challenge");

        await _attestation.Complete(new PublicKeyCredential
        {
            Id = request.Id,
            RawId = request.RawId,
            Response = new AuthenticatorAttestationResponse
            {
                AttestationObject = request.Response.AttestationObject,
                ClientDataJson = request.Response.ClientDataJson,
                Signature = request.Response.Signature,
                UserHandler = request.Response.UserHandler,
            }
        },
        expectedChallenge);

        return Ok(ServerResponse.Create());
    }
}