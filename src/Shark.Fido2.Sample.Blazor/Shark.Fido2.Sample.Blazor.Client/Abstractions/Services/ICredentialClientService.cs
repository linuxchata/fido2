using Shark.Fido2.Sample.Blazor.Client.Models;
using Shark.Fido2.Sample.Blazor.Client.ViewModels;

namespace Shark.Fido2.Sample.Blazor.Client.Abstractions.Services;

/// <summary>
/// The interface representing the logic to retrieve credential details.
/// </summary>
public interface ICredentialClientService
{
    /// <summary>
    /// Gets credential details by the credential identifier.
    /// </summary>
    /// <param name="baseUri">The base URI of the server.</param>
    /// <param name="id">The credential identifier.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The response.</returns>
    Task<Response<CredentialDetailsViewModel>> Get(Uri baseUri, string id, CancellationToken cancellationToken);
}
