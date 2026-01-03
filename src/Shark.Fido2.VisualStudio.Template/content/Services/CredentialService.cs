using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Sample.VisualStudio.Template.Services;

public sealed class CredentialService(ICredentialRepository credentialRepository) : ICredentialService
{
    public async Task<Credential?> Get(string credentialId, CancellationToken cancellationToken)
    {
        var id = credentialId.FromBase64Url();
        return await credentialRepository.Get(id, cancellationToken);
    }
}
