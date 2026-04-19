using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.InMemory;
using Shark.Fido2.Metadata.Core.Abstractions;

namespace Shark.Fido2.Core.Integration.Tests;

/// <summary>
/// Integration tests for FIDO Metadata Service.
/// </summary>
[TestFixture]
public class FidoMetadataServiceIntegrationTests
{
    private readonly Guid _aaGuid = new Guid("6028b017-b1d4-4c02-b4b3-afcdafc96bb2");

    private ServiceProvider _serviceProvider = null!;

    /// <summary>
    /// Setup for the tests.
    /// </summary>
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
        var service = _serviceProvider.GetRequiredService<IMetadataCachedService>();

        // Act
        var result = await service.Get(_aaGuid, CancellationToken.None);

        // Assert
        Assert.That(service.GetType().Name, Is.EqualTo("MetadataCachedService"));
        Assert.That(result, Is.Not.Null);
    }
}
