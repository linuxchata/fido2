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
internal class CredentialsIntegrationTests
{
    private const string PackedWindowsHelloAttestation = "PackedWindowsHelloAttestation.json";
    private const string PackedWindowsHelloCreationOptions = "PackedWindowsHelloCreationOptions.json";
    private const string PackedWindowsHelloAssertion = "PackedWindowsHelloAssertion.json";
    private const string PackedWindowsHelloRequestOptions = "PackedWindowsHelloRequestOptions.json";

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
    public async Task BeginRegistration_WhenPackedWindowsHelloAttestation_ThenReturnsSuccess()
    {
        // Arrange
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = "UserName",
            DisplayName = "DisplayName",
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = null,
                RequireResidentKey = false,
                ResidentKey = 0,
                UserVerification = UserVerificationRequirement.Required,
            },
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act
        var result = await attestation.BeginRegistration(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.RelyingParty.Id, Is.EqualTo("localhost"));
        Assert.That(result.RelyingParty.Name, Is.EqualTo("Shark Corporation"));
        Assert.That(result.User.Id, Has.Length.EqualTo(8));
        Assert.That(result.User.Name, Is.EqualTo(request.UserName));
        Assert.That(result.User.DisplayName, Is.EqualTo(request.DisplayName));
        Assert.That(result.Challenge, Has.Length.EqualTo(32));
        Assert.That(result.PublicKeyCredentialParams, Is.Not.Empty);
        Assert.That(result.PublicKeyCredentialParams, Has.Length.AtLeast(1));
        Assert.That(result.Timeout, Is.EqualTo(30000));
        Assert.That(result.AuthenticatorSelection.AuthenticatorAttachment, Is.Null);
        Assert.That(result.AuthenticatorSelection.ResidentKey, Is.EqualTo(ResidentKeyRequirement.Discouraged));
        Assert.That(result.AuthenticatorSelection.RequireResidentKey, Is.False);
        Assert.That(result.AuthenticatorSelection.UserVerification, Is.EqualTo(UserVerificationRequirement.Required));
        Assert.That(result.Attestation, Is.EqualTo(AttestationConveyancePreference.Direct));
    }

    [Test]
    public async Task CompleteRegistration_WhenPackedWindowsHelloAttestation_ThenReturnsSuccess()
    {
        // Arrange
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(PackedWindowsHelloAttestation);
        var creationOptions = DataReader.ReadCreationOptions(PackedWindowsHelloCreationOptions);

        // Act
        var result = await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task CompleteRegistration_WhenPackedWindowsHelloAttestationUsedTwice_ThenReturnsFailure()
    {
        // Arrange
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(PackedWindowsHelloAttestation);
        var creationOptions = DataReader.ReadCreationOptions(PackedWindowsHelloCreationOptions);

        await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        // Act
        var result = await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Credential has already been registered"));
    }

    [Test]
    public async Task BeginAuthentication_WhenPackedWindowsHelloAssertion_ThenReturnsSuccess()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();

        var request = new PublicKeyCredentialRequestOptionsRequest
        {
            UserName = "UserName",
            UserVerification = UserVerificationRequirement.Required,
        };

        // Act
        var result = await assertion.BeginAuthentication(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Challenge, Has.Length.EqualTo(32));
        Assert.That(result.Timeout, Is.EqualTo(30000));
        Assert.That(result.RpId, Is.EqualTo("localhost"));
        Assert.That(result.AllowCredentials, Is.Empty);
        Assert.That(result.Username, Is.EqualTo("UserName"));
        Assert.That(result.UserVerification, Is.EqualTo(UserVerificationRequirement.Required));
        Assert.That(result.Extensions, Is.Not.Null);
        Assert.That(result.Extensions.AppId, Is.Null);
        Assert.That(result.Extensions.AppIdExclude, Is.Null);
        Assert.That(result.Extensions.CredentialProperties, Is.Null);
        Assert.That(result.Extensions.LargeBlob, Is.Null);
        Assert.That(result.Extensions.UserVerificationMethod, Is.False);
    }

    [Test]
    public async Task CompleteAuthentication_WhenPackedWindowsHelloAssertion_ThenReturnsSuccess()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(PackedWindowsHelloAttestation);
        var creationOptions = DataReader.ReadCreationOptions(PackedWindowsHelloCreationOptions);
        await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        var assertionData = DataReader.ReadAssertionData(PackedWindowsHelloAssertion);
        var requestOptions = DataReader.ReadRequestOptions(PackedWindowsHelloRequestOptions);

        // Act
        var result = await assertion.CompleteAuthentication(assertionData, requestOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task CompleteAuthentication_WhenPackedWindowsHelloAssertionUsedTwice_ThenReturnsFailure()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(PackedWindowsHelloAttestation);
        var creationOptions = DataReader.ReadCreationOptions(PackedWindowsHelloCreationOptions);
        await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        var assertionData = DataReader.ReadAssertionData(PackedWindowsHelloAssertion);
        var requestOptions = DataReader.ReadRequestOptions(PackedWindowsHelloRequestOptions);

        await assertion.CompleteAuthentication(assertionData, requestOptions, CancellationToken.None);

        // Act
        var result = await assertion.CompleteAuthentication(assertionData, requestOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Signature counter of the authenticator is less or equal to stored signature count. The authenticator may be cloned"));
    }
}
