using System.Diagnostics.CodeAnalysis;
using Amazon;
using Amazon.DynamoDBv2;
using Amazon.Runtime;

namespace Shark.Fido2.DynamoDB;

[ExcludeFromCodeCoverage]
internal static class AmazonDynamoDbClientFactory
{
    public static IAmazonDynamoDB GetClient(AmazonDynamoDbConfiguration configuration)
    {
        var credentials = new BasicAWSCredentials(configuration.AccessKey, configuration.SecretKey);

        var regionEndpoint = RegionEndpoint.GetBySystemName(configuration.AwsRegion);
        var amazonDynamoDBConfig = new AmazonDynamoDBConfig
        {
            RegionEndpoint = regionEndpoint,
            ConnectTimeout = TimeSpan.FromSeconds(configuration.ConnectTimeoutInSeconds),
            MaxErrorRetry = configuration.MaxErrorRetry,
        };

        return new AmazonDynamoDBClient(credentials, amazonDynamoDBConfig);
    }
}
