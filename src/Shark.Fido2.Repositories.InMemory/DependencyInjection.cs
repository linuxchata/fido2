using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Repositories;

namespace Shark.Fido2.Repositories.InMemory;

public static class DependencyInjection
{
    public static void RegisterInMemoryRepositories(this IServiceCollection services)
    {
        services.AddTransient<ICredentialRepository, CredentialRepository>();
    }
}
