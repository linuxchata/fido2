using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Repositories;

/// <summary>
/// Defines methods for managing credentials.
/// </summary>
public interface ICredentialRepository
{
    /// <summary>
    /// Gets a credential by identifier.
    /// </summary>
    /// <param name="credentialId">The identifier of the credential to retrieve.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The credential if found; otherwise, null.</returns>
    Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a list of credentials associated with a username.
    /// </summary>
    /// <param name="username">The username associated with the credentials to retrieve.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A list of credentials.</returns>
    Task<List<Credential>> Get(string username, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a new credential.
    /// </summary>
    /// <param name="credential">The credential.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task Add(Credential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the signature counter of an existing credential.
    /// </summary>
    /// <param name="credential">The credential.</param>
    /// <param name="signCount">The new signature counter value.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task UpdateSignCount(Credential credential, uint signCount, CancellationToken cancellationToken = default);
}
