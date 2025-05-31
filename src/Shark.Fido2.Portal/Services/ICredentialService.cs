using Shark.Fido2.Domain;

namespace Shark.Fido2.Portal.Services;

public interface ICredentialService
{
    Task<Credential?> Get(byte[] id, CancellationToken cancellationToken);
}
