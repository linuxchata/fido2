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
    public void Validate_WhenRelyingPartyIdIsEmpty_ThenReturnsFailure(string relyingPartyId)
    {
        // Arrange
        var configuration = new Fido2Configuration
        {
            RelyingPartyId = relyingPartyId,
            RelyingPartyIdName = "Test RP",
            Origins = ["localhost"],
        };

        // Act
        var result = _sut.Validate(null, configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("'RelyingPartyId' configuration key must be defined"));
    }

    [Test]
    [TestCase("https://localhost")]
    [TestCase("http://localhost")]
    public void Validate_WhenRelyingPartyIdHasScheme_ThenReturnsFailure(string relyingPartyId)
    {
        // Arrange
        var configuration = new Fido2Configuration
        {
            RelyingPartyId = relyingPartyId,
            RelyingPartyIdName = "Test RP",
            Origins = ["localhost"],
        };

        // Act
        var result = _sut.Validate(null, configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("'RelyingPartyId' configuration key must not include scheme"));
    }

    [Test]
    [TestCase("localhost:0")]
    [TestCase("localhost:80")]
    [TestCase("localhost:8080")]
    [TestCase("localhost:43589")]
    public void Validate_WhenRelyingPartyIdHasPort_ThenReturnsFailure(string relyingPartyId)
    {
        // Arrange
        var configuration = new Fido2Configuration
        {
            RelyingPartyId = relyingPartyId,
            RelyingPartyIdName = "Test RP",
            Origins = ["localhost"],
        };

        // Act
        var result = _sut.Validate(null, configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("'RelyingPartyId' configuration key must not include port number"));
    }

    [Test]
    public void Validate_WhenOriginsIsNull_ThenReturnsFailure()
    {
        // Arrange
        var configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origins = null!,
        };

        // Act
        var result = _sut.Validate(null, configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("'Origins' configuration key must include at least one origin"));
    }

    [Test]
    public void Validate_WhenOriginsAreEmpty_ThenReturnsFailure()
    {
        // Arrange
        var configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origins = [],
        };

        // Act
        var result = _sut.Validate(null, configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("'Origins' configuration key must include at least one origin"));
    }

    [Test]
    [TestCase(null!)]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenOriginIsEmpty_ThenReturnsFailure(string origin)
    {
        // Arrange
        var configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origins = [origin],
        };

        // Act
        var result = _sut.Validate(null, configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("'Origins' configuration key must not include empty values"));
    }

    [Test]
    public void Validate_WhenAlgorithmsSetIsInvalid_ThenReturnsFailure()
    {
        // Arrange
        var configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origins = ["localhost"],
            AlgorithmsSet = "Unssuported",
        };

        // Act
        var result = _sut.Validate(null, configuration);

        // Assert
        Assert.That(result.Failed, Is.True);
        Assert.That(result.FailureMessage, Does.Contain("'AlgorithmsSet' configuration key must be one of the following values: Required, Recommended, Extended"));
    }

    [Test]
    [TestCase(null!)]
    [TestCase("")]
    [TestCase("   ")]
    [TestCase("Required")]
    [TestCase("Recommended")]
    [TestCase("Extended")]

    public void Validate_WhenConfigurationIsValid_ThenReturnsSuccess(string algorithmsSet)
    {
        // Arrange
        var configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origins = ["localhost"],
            AlgorithmsSet = algorithmsSet,
        };

        // Act
        var result = _sut.Validate(null, configuration);

        // Assert
        Assert.That(result.Succeeded, Is.True);
    }
}