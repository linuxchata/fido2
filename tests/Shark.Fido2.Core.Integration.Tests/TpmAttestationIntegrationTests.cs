using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.InMemory;
using Shark.Fido2.Tests.Common.DataReaders;

namespace Shark.Fido2.Core.Integration.Tests;

/// <summary>
/// Source: Windows 11 Windows Hello authenticator.
/// </summary>
[TestFixture]
internal class TpmAttestationIntegrationTests
{
    private const string TpmAttestation = "TpmAttestation.json";
    private const string TpmCreationOptions = "TpmCreationOptions.json";
    private const string TpmAssertion = "TpmAssertion.json";
    private const string TpmRequestOptions = "TpmRequestOptions.json";

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
    public async Task BeginRegistration_WhenTpmAttestation_ThenReturnsSuccess()
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
    public async Task CompleteRegistration_WhenTpmAttestation_ThenReturnsSuccess()
    {
        // Arrange
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(TpmAttestation);
        var creationOptions = DataReader.ReadCreationOptions(TpmCreationOptions);

        // Act
        var result = await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task CompleteRegistration_WhenTpmAttestationUsedTwice_ThenReturnsFailure()
    {
        // Arrange
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(TpmAttestation);
        var creationOptions = DataReader.ReadCreationOptions(TpmCreationOptions);

        await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        // Act
        var result = await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Credential has already been registered"));
    }

    [Test]
    public async Task BeginAuthentication_WhenTpmAssertion_ThenReturnsSuccess()
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
    public async Task CompleteAuthentication_WhenTpmAssertion_ThenReturnsSuccess()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(TpmAttestation);
        var creationOptions = DataReader.ReadCreationOptions(TpmCreationOptions);
        await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        var assertionData = DataReader.ReadAssertionData(TpmAssertion);
        var requestOptions = DataReader.ReadRequestOptions(TpmRequestOptions);

        // Act
        var result = await assertion.CompleteAuthentication(assertionData, requestOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task CompleteAuthentication_WhenTpmAssertionUsedTwice_ThenReturnsFailure()
    {
        // Arrange
        var assertion = _serviceProvider.GetRequiredService<IAssertion>();
        var attestation = _serviceProvider.GetRequiredService<IAttestation>();

        var attestationData = DataReader.ReadAttestationData(TpmAttestation);
        var creationOptions = DataReader.ReadCreationOptions(TpmCreationOptions);
        await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

        var assertionData = DataReader.ReadAssertionData(TpmAssertion);
        var requestOptions = DataReader.ReadRequestOptions(TpmRequestOptions);

        await assertion.CompleteAuthentication(assertionData, requestOptions, CancellationToken.None);

        // Act
        var result = await assertion.CompleteAuthentication(assertionData, requestOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("The authenticator's signature counter value is less than or equal to the previously stored count, indicating that the device may have been cloned or duplicated."));
    }
}
