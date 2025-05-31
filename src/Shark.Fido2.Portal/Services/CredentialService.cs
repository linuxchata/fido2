using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Portal.Services;

public sealed class CredentialService : ICredentialService
{
    private readonly ICredentialRepository _credentialRepository;

    public CredentialService(ICredentialRepository credentialRepository)
    {
        _credentialRepository = credentialRepository;
    }

    public async Task<Credential?> Get(byte[] id, CancellationToken cancellationToken)
    {
        return await _credentialRepository.Get(id, cancellationToken);
    }
}
