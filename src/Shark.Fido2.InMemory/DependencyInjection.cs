using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Repositories;

namespace Shark.Fido2.InMemory;

public static class DependencyInjection
{
    public static void UseFido2InMemoryStore(this IServiceCollection services)
    {
        if (services.Any(s => s.ServiceType == typeof(CredentialRepository)))
        {
            throw new InvalidOperationException("Credential repository can only be registered once.");
        }

        services.AddDistributedMemoryCache();

        services.AddTransient<ICredentialRepository, CredentialRepository>();
    }
}
