using System.Net.Mime;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Domain;
using Shark.Fido2.Responses;
using Shark.Sample.Fido2.Requests;

namespace Shark.Sample.Fido2.Controllers;

/// <summary>
/// Attestation (registration)
/// </summary>
[Route("[controller]")]
[ApiController]
public class AttestationController(IAttestationService attestationService) : ControllerBase
{
    private readonly IAttestationService _attestationService = attestationService;

    /// <summary>
    /// Gets credential creation options
    /// </summary>
    /// <returns>The HTTP response.</returns>
    [HttpPost("options")]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Options()
    {
        var credentialOptions = _attestationService.GetOptions();

        var response = new CredentialGetOptionsResponse
        {
            Challenge = credentialOptions.Challenge,
            RelyingParty = new RelyingPartyResponse
            {
                Identifier = "localhost",
                Name = "Example CORP",
            },
            User = new UserResponse
            {
                Identifier = Guid.NewGuid().ToString(),
                Name = "johndoe@example.com",
                DisplayName = "John Doe",
            }
        };

        HttpContext.Session.SetString("Challenge", response.Challenge);

        return Ok(response);
    }

    /// <summary>
    /// Validate credential
    /// </summary>
    /// <param name="request"></param>
    /// <returns>The HTTP response.</returns>
    [HttpPost("result")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Result(PublicKeyCredentialResponse request)
    {
        // The server will validate challenges, origins, signatures and the rest of
        // the ServerAuthenticatorAttestationResponse according to the algorithm
        // described in section 7.1 of the [Webauthn] specs, and will respond with
        // the appropriate ServerResponse message.

        var expectedChallenge = HttpContext.Session.GetString("Challenge");

        var response = new CredentialValidateResponse();

        _attestationService.Complete(new PublicKeyCredential
        {
            Id = request.Id,
            RawId = request.RawId,
            Response = new Shark.Fido2.Domain.AuthenticatorAttestationResponse
            {
                AttestationObject = request.Response.AttestationObject,
                ClientDataJson = request.Response.ClientDataJson,
                Signature = request.Response.Signature,
                UserHandler = request.Response.UserHandler,
            }
        },
        expectedChallenge);

        response.Status = ResponseStatus.Failed;
        response.Status = ResponseStatus.Ok;

        return Ok(response);
    }
}