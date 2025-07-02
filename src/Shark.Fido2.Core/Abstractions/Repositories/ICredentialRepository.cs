using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Repositories;

/// <summary>
/// Defines methods for managing credentials.
/// </summary>
public interface ICredentialRepository
{
    /// <summary>
    /// Gets a credential by credential identifier.
    /// </summary>
    /// <param name="credentialId">The identifier of the credential.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The credential if found; otherwise, null.</returns>
    Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a list of credentials associated with a username.
    /// </summary>
    /// <param name="userName">The username associated with the credentials.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A list of credential descriptors (a lightweight descriptor of a credential).</returns>
    Task<List<CredentialDescriptor>> Get(string userName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks whether a credential exists by credential identifier.
    /// </summary>
    /// <param name="credentialId">The identifier of the credential.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>True if a credential exists; otherwise, false.</returns>
    Task<bool> Exists(byte[]? credentialId, CancellationToken cancellationToken = default);

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
    /// <param name="credentialId">The identifier of the credential.</param>
    /// <param name="signCount">The new signature counter value.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task UpdateSignCount(byte[] credentialId, uint signCount, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the last used timestamp of an existing credential.
    /// </summary>
    /// <param name="credentialId">The identifier of the credential.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task UpdateLastUsedAt(byte[] credentialId, CancellationToken cancellationToken = default);
}
