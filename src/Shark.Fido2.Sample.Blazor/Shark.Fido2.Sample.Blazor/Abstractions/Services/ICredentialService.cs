using Shark.Fido2.Domain;

namespace Shark.Fido2.Sample.Blazor.Abstractions.Services;

public interface ICredentialService
{
    Task<Credential?> Get(byte[] id, CancellationToken cancellationToken);
}
