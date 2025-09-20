using System.Diagnostics.CodeAnalysis;

namespace Shark.Fido2.DynamoDB;

[ExcludeFromCodeCoverage]
internal class AmazonDynamoDbConfiguration
{
    public string AwsRegion { get; set; } = null!;

    public string AccessKey { get; set; } = null!;

    public string SecretKey { get; set; } = null!;

    public int ConnectTimeoutInSeconds { get; set; } = 60;

    public int MaxErrorRetry { get; set; } = 10;
}
