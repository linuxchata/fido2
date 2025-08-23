using Shark.Fido2.Domain;

namespace Shark.Fido2.Sample.Blazor.Abstractions.Services;

/// <summary>
/// The interface representing the logic to retrieve credential details.
/// </summary>
public interface ICredentialService
{
    /// <summary>
    /// Gets credential details by the credential identifier.
    /// </summary>
    /// <param name="id">The credential identifier.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The credential details.</returns>
    Task<Credential?> Get(byte[] id, CancellationToken cancellationToken);
}
