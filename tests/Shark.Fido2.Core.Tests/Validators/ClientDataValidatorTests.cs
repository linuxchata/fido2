using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
public class ClientDataValidatorTests
{
    private ClientDataValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        var fido2ConfigurationMock = new Fido2Configuration
        {
            Origin = "localhost",
        };

        _sut = new ClientDataValidator(Options.Create(fido2ConfigurationMock));
    }

    [Test]
    public void Validate_WhenClientDataValid_ThenReturnsValidResult()
    {
        // Arrange
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
        };

        // Act
        var result = _sut.Validate(clientDataModel, $"{expectedChallenge}==");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenClientDataInvalid_ThenReturnsInvalidResult()
    {
        // Arrange
        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = "t2pJGIQ7Y4DXF2b98tnBjg",
            Origin = "https://localhost:4000",
            CrossOrigin = false,
        };

        // Act
        var result = _sut.Validate(clientDataModel, "1epJGYQ2Y9DXF1b98tnGwr==");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.Not.Null);
    }
}