using System.Net.Mime;
using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Sample.Blazor.Abstractions.Services;
using Shark.Fido2.Sample.Blazor.Responses;

namespace Shark.Fido2.Sample.Blazor.Controllers;

/// <summary>
/// Credentials Details.
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class CredentialsDetailsController(ICredentialService credentialService) : ControllerBase
{
    /// <summary>
    /// Gets credential details by credential identifier.
    /// </summary>
    /// <param name="id">The credential identifier as base64url string.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    [HttpGet("{id}")]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> GetCredential(string id, CancellationToken cancellationToken)
    {
        try
        {
            var credentialIdBytes = id.FromBase64Url();

            var credential = await credentialService.Get(credentialIdBytes, cancellationToken);
            if (credential == null)
            {
                return NotFound("Credential not found");
            }

            var response = new CredentialDetailsResponse
            {
                CredentialId = credential.CredentialId.ToBase64Url(),
                UserHandle = credential.CredentialId.ToBase64Url(),
                UserName = credential.UserName,
                UserDisplayName = credential.UserDisplayName,
                SignCount = credential.SignCount,
                Algorithm = PublicKeyAlgorithms.Get(credential.CredentialPublicKey.Algorithm),
                Transports = credential.Transports ?? [],
                CreatedAt = credential.CreatedAt,
                UpdatedAt = credential.UpdatedAt,
                LastUsedAt = credential.LastUsedAt,
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            return BadRequest($"Error retrieving credential: {ex.Message}");
        }
    }
}