using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Integration.Tests.DataReaders;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.InMemory;

namespace Shark.Fido2.Core.Integration.Tests;

[TestFixture]
internal class AssertionIntegrationTests
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
    public async Task RequestOptions_WhenPackedWindowsHelloAssertion_ThenReturnsSuccess()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();

        var request = new PublicKeyCredentialRequestOptionsRequest
        {
        };

        // Act
        var result = await assertion.RequestOptions(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Challenge, Has.Length.EqualTo(24));
        Assert.That(result.Timeout, Is.EqualTo(30000));
    }

    [Test]
    public async Task Complete_WhenPackedWindowsHelloAttestation_ThenReturnsSuccess()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();

        var assertionData = DataReader.ReadAssertionData("PackedWindowsHelloAssertion.json");
        var requestOptions = DataReader.ReadRequestOptions("PackedWindowsHelloRequestOptions.json");

        // Act
        var result = await assertion.Complete(assertionData, requestOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Complete_WhenPackedWindowsHelloAttestationUsedTwice_ThenReturnsFailure()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();

        var assertionData = DataReader.ReadAssertionData("PackedWindowsHelloAssertion.json");
        var requestOptions = DataReader.ReadRequestOptions("PackedWindowsHelloRequestOptions.json");

        await assertion.Complete(assertionData, requestOptions, CancellationToken.None);

        // Act
        var result = await assertion.Complete(assertionData, requestOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Credential has already been registered"));
    }
}
