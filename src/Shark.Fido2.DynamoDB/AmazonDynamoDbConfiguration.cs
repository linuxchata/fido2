namespace Shark.Fido2.DynamoDB;

internal class AmazonDynamoDbConfiguration
{
    public string AwsRegion { get; set; } = null!;

    public string AccessKey { get; set; } = null!;

    public string SecretKey { get; set; } = null!;
}
