using Shark.Fido2.Core.Configurations;

namespace Shark.Fido2.Core.Tests.Configurations;

[TestFixture]
internal class Fido2ConfigurationValidatorTests
{
    private Fido2ConfigurationValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new Fido2ConfigurationValidator();
    }

    [Test]
    [TestCase(null!)]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenRelyingPartyIdIsEmpty_ReturnsFailure(string relyingPartyId)
    {
        // Arrange
        var fido2Configuration = new Fido2Configuration
        {
            RelyingPartyId = relyingPartyId,
            RelyingPartyIdName = "Test RP",
            Origin = "localhost",
        };

        // Act
        var result = _sut.Validate(null, fido2Configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("RelyingPartyId must be defined in the configuration"));
    }

    [Test]
    [TestCase("https://localhost")]
    [TestCase("http://localhost")]
    public void Validate_WhenRelyingPartyIdHasScheme_ReturnsFailure(string relyingPartyId)
    {
        // Arrange
        var fido2Configuration = new Fido2Configuration
        {
            RelyingPartyId = relyingPartyId,
            RelyingPartyIdName = "Test RP",
            Origin = "localhost",
        };

        // Act
        var result = _sut.Validate(null, fido2Configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("RelyingPartyId must not include scheme"));
    }

    [Test]
    [TestCase("localhost:")]
    [TestCase("localhost:abc")]
    [TestCase("localhost:0")]
    [TestCase("localhost:8080")]
    public void Validate_WhenRelyingPartyIdHasPort_ReturnsFailure(string relyingPartyId)
    {
        // Arrange
        var fido2Configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost:8080",
            RelyingPartyIdName = "Test RP",
            Origin = "localhost",
        };

        // Act
        var result = _sut.Validate(null, fido2Configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("RelyingPartyId must not include port number"));
    }

    [Test]
    [TestCase(null!)]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenOriginIsEmpty_ReturnsFailure(string origin)
    {
        // Arrange
        var fido2Configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origin = origin,
        };

        // Act
        var result = _sut.Validate(null, fido2Configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("Origin must be defined in the configuration"));
    }

    [Test]
    public void Validate_WhenFido2ConfigurationIsValid_ReturnsSuccess()
    {
        // Arrange
        var fido2Configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origin = "localhost",
        };

        // Act
        var result = _sut.Validate(null, fido2Configuration);

        // Assert
        Assert.That(result.Succeeded, Is.True);
    }
}