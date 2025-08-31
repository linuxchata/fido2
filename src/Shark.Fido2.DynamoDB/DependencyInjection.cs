using System.Diagnostics.CodeAnalysis;
using Amazon.DynamoDBv2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions.Repositories;

namespace Shark.Fido2.DynamoDB;

[ExcludeFromCodeCoverage]
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

        services.AddSingleton<IAmazonDynamoDB>(sp =>
        {
            var configuration = sp.GetRequiredService<IConfiguration>();
            var amazonDynamoDbConfiguration = new AmazonDynamoDbConfiguration();
            configuration.GetSection(amazonDynamoDbConfigurationKeyName).Bind(amazonDynamoDbConfiguration);
            return AmazonDynamoDbClientFactory.GetClient(amazonDynamoDbConfiguration);
        });

        services.AddTransient<ICredentialRepository, CredentialRepository>();
    }
}