using Shark.Fido2.Domain;

namespace Shark.Fido2.Sample.Template.Services;

public interface ICredentialService
{
    Task<Credential?> Get(string credentialId, CancellationToken cancellationToken);
}
