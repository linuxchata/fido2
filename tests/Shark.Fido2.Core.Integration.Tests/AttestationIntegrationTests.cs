using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Integration.Tests.DataReaders;
using Shark.Fido2.InMemory;

namespace Shark.Fido2.Core.Integration.Tests;

[TestFixture]
internal class AttestationIntegrationTests
{
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
        _serviceProvider = services.BuildServiceProvider();
    }

    [TearDown]
    public void TearDown()
    {
        _serviceProvider!.Dispose();
    }

    [Test]
    public async Task Complete_WhenPackedWindowsHelloAttestation_ThenReturnsSuccess()
    {
        // Arrange
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData("PackedWindowsHelloAttestation.json");
        var creationOptions = DataReader.ReadCreationOptions("PackedWindowsHelloCreationOptions.json");

        // Act
        var result = await attestation.Complete(
            attestationData,
            creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}
