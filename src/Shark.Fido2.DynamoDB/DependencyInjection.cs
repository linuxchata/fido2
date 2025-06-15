using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.DynamoDB.Abstractions;

namespace Shark.Fido2.DynamoDB;

public static class DependencyInjection
{
    public static void AddFido2DynamoDB(
        this IServiceCollection services,
        string amazonDynamoDbConfigurationKeyName = "AmazonDynamoDbConfiguration")
    {
        if (services.Any(s => s.ServiceType == typeof(ICredentialRepository)))
        {
            throw new InvalidOperationException("Credential repository can only be registered once.");
        }

        services.AddSingleton<IAmazonDynamoDbClientFactory>(sp =>
        {
            var configuration = sp.GetRequiredService<IConfiguration>();
            var amazonDynamoDbConfiguration = new AmazonDynamoDbConfiguration();
            configuration.GetSection(amazonDynamoDbConfigurationKeyName).Bind(amazonDynamoDbConfiguration);
            return new AmazonDynamoDbClientFactory(amazonDynamoDbConfiguration);
        });

        services.AddTransient<ICredentialRepository, CredentialRepository>();
    }
}