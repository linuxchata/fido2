using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Repositories;

public interface ICredentialRepository
{
    Task<Credential?> Get(byte[]? id, CancellationToken cancellationToken = default);

    Task<List<Credential>> Get(string username, CancellationToken cancellationToken = default);

    Task Add(Credential credential, CancellationToken cancellationToken = default);

    Task UpdateSignCount(Credential credential, uint signCount, CancellationToken cancellationToken = default);
}
