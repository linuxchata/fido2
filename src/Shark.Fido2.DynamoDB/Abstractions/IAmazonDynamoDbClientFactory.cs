using Amazon.DynamoDBv2;

namespace Shark.Fido2.DynamoDB.Abstractions;

internal interface IAmazonDynamoDbClientFactory
{
    IAmazonDynamoDB GetClient();
}
