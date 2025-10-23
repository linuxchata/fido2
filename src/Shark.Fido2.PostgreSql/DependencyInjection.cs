using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Repositories;

namespace Shark.Fido2.PostgreSql;

[ExcludeFromCodeCoverage]
public static class DependencyInjection
{
    public static void AddFido2PostgreSql(
        this IServiceCollection services,
        string connectionStringName = "DefaultConnection")
    {
        if (services.Any(s => s.ServiceType == typeof(ICredentialRepository)))
        {
            throw new InvalidOperationException("Credential repository can only be registered once.");
        }

        services.AddSingleton(sp =>
        {
            var configuration = sp.GetRequiredService<IConfiguration>();
            var connectionString = configuration.GetConnectionString(connectionStringName)
                ?? throw new InvalidOperationException("Connection string is missing");
            return new DatabaseSettings { DefaultConnection = connectionString, };
        });

        services.AddTransient<ICredentialRepository, CredentialRepository>();
    }
}
