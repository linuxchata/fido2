using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.InMemory;
using Shark.Fido2.Tests.Common.DataReaders;

namespace Shark.Fido2.Core.Performance.Tests;

[TestFixture]
internal class NoneAttestationIntegrationTests
{
    private const string NoneAttestation = "NoneAttestation.json";
    private const string NoneCreationOptions = "NoneCreationOptions.json";
    private const string NoneAssertion = "NoneAssertion.json";
    private const string NoneRequestOptions = "NoneRequestOptions.json";

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
        services.AddLogging();
        _serviceProvider = services.BuildServiceProvider();
    }

    [TearDown]
    public void TearDown()
    {
        _serviceProvider!.Dispose();
    }

    [Test]
    public async Task CompleteRegistration_WhenNoneAttestation_ThenReturnsSuccess()
    {
        // Arrange
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(NoneAttestation);
        var creationOptions = DataReader.ReadCreationOptions(NoneCreationOptions);

        // Act
        var result = await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public async Task CompleteAuthentication_WhenNoneAssertion_ThenReturnsSuccess()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(NoneAttestation);
        var creationOptions = DataReader.ReadCreationOptions(NoneCreationOptions);
        await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        var assertionData = DataReader.ReadAssertionData(NoneAssertion);
        var requestOptions = DataReader.ReadRequestOptions(NoneRequestOptions);

        // Act
        var result = await assertion.CompleteAuthentication(assertionData, requestOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
    }
}
