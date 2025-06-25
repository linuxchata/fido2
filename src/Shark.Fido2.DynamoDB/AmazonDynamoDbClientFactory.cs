using Amazon;
using Amazon.DynamoDBv2;
using Amazon.Runtime;
using Shark.Fido2.DynamoDB.Abstractions;

namespace Shark.Fido2.DynamoDB;

internal class AmazonDynamoDbClientFactory : IAmazonDynamoDbClientFactory
{
    private readonly AmazonDynamoDbConfiguration _configuration;

    public AmazonDynamoDbClientFactory(AmazonDynamoDbConfiguration configuration)
    {
        _configuration = configuration;
    }

    public AmazonDynamoDBClient GetClient()
    {
        var credentials = new BasicAWSCredentials(_configuration.AccessKey, _configuration.SecretKey);
        var regionEndpoint = RegionEndpoint.GetBySystemName(_configuration.AwsRegion);
        return new AmazonDynamoDBClient(credentials, regionEndpoint);
    }
}
