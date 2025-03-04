using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Repositories;

public interface ICredentialRepository
{
    Task<Credential?> Get(byte[]? id);

    Task<List<Credential>> Get(string username);

    Task Add(Credential credential);

    Task UpdateSignCount(Credential credential, uint signCount);
}
