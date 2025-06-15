using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Repositories;

namespace Shark.Fido2.DynamoDB;

public static class DependencyInjection
{
    public static void AddFido2DynamoDB(this IServiceCollection services)
    {
        if (services.Any(s => s.ServiceType == typeof(ICredentialRepository)))
        {
            throw new InvalidOperationException("Credential repository can only be registered once.");
        }
    }
}