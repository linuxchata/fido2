using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Shark.Fido2.ConvenienceMetadata.Core;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.InMemory;

namespace Shark.Fido2.Core.Integration.Tests;

[TestFixture]
public class ConvenienceMetadataCachedServiceTests
{
    private readonly Guid _aaGuid = new("6028b017-b1d4-4c02-b4b3-afcdafc96bb2");

    private ServiceProvider _serviceProvider = null!;

    [SetUp]
    public void Setup()
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json")
            .Build();

        var services = new ServiceCollection();
        services.AddFido2(configuration);
        services.AddFido2InMemoryStore();
        services.AddFido2ConvenienceMetadataService(configuration);
        _serviceProvider = services.BuildServiceProvider();
    }

    [TearDown]
    public void TearDown()
    {
        _serviceProvider.Dispose();
    }

    [Test]
    public async Task Get_ThenFetchesAndParsesRealBlob()
    {
        // Arrange
        var service = _serviceProvider.GetRequiredService<IConvenienceMetadataCachedService>();

        // Act
        var result = await service.Get(_aaGuid, It.IsAny<CancellationToken>());

        // Assert
        Assert.That(service.GetType().Name, Is.EqualTo("ConvenienceMetadataCachedService"));
        Assert.That(result, Is.Not.Null);
    }
}
