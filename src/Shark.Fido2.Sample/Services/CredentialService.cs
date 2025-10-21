using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Domain;
using Shark.Fido2.Sample.Abstractions.Services;

namespace Shark.Fido2.Sample.Services;

public sealed class CredentialService : ICredentialService
{
    private readonly ICredentialRepository _credentialRepository;

    public CredentialService(ICredentialRepository credentialRepository)
    {
        _credentialRepository = credentialRepository;
    }

    public async Task<Credential?> Get(string credentialId, CancellationToken cancellationToken)
    {
        var id = credentialId.FromBase64Url();
        return await _credentialRepository.Get(id, cancellationToken);
    }
}
