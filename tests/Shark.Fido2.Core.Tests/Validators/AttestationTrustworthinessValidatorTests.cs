using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
public class AttestationTrustworthinessValidatorTests
{
    private AttestationTrustworthinessValidator _sut = null!;
    private Fido2Configuration _configuration;

    [SetUp]
    public void Setup()
    {
        _configuration = new Fido2Configuration();
        var options = Options.Create(_configuration);
        _sut = new AttestationTrustworthinessValidator(options);
    }

    [Test]
    public void Validate_WhenNullAttestationStatementResult_ThenReturnsInvalid()
    {
        // Act
        var result = _sut.Validate(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation statement result cannot be null"));
    }

    [TestCase(true)]
    [TestCase(false)]
    public void Validate_WhenNoneAttestation_ThenReturnsExpectedResult(bool allowNoneAttestation)
    {
        // Arrange
        _configuration.AllowNoneAttestation = allowNoneAttestation;
        var attestationResult = new AttestationStatementInternalResult(AttestationTypeEnum.None);

        // Act
        var result = _sut.Validate(attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.EqualTo(allowNoneAttestation));
        if (!allowNoneAttestation)
        {
            Assert.That(result.Message, Is.EqualTo("None attestation type is not allowed under current policy"));
        }
    }

    [TestCase(true)]
    [TestCase(false)]
    public void Validate_WhenSelfAttestation_ThenReturnsExpectedResult(bool allowSelfAttestation)
    {
        // Arrange
        _configuration.AllowSelfAttestation = allowSelfAttestation;
        var attestationResult = new AttestationStatementInternalResult(AttestationTypeEnum.Self);

        // Act
        var result = _sut.Validate(attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.EqualTo(allowSelfAttestation));
        if (!allowSelfAttestation)
        {
            Assert.That(result.Message, Is.EqualTo("Self attestation type is not allowed under current policy"));
        }
    }

    [Test]
    public void Validate_WhenBasicAttestationWithoutTrustPath_ThenReturnsInvalid()
    {
        // Arrange
        var attestationResult = new AttestationStatementInternalResult(AttestationTypeEnum.Basic);

        // Act
        var result = _sut.Validate(attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Trust path is required for Basic attestation type"));
    }

    [Test]
    public void Validate_WhenBasicAttestationWithEmptyTrustPath_ThenReturnsInvalid()
    {
        // Arrange
        var attestationResult = new AttestationStatementInternalResult(
            AttestationTypeEnum.Basic,
            Array.Empty<X509Certificate2>());

        // Act
        var result = _sut.Validate(attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Trust path is required for Basic attestation type"));
    }

    [Test]
    public void Validate_WhenBasicAttestationWithTrustPath_ThenReturnsValid()
    {
        // Arrange
        var attestationResult = new AttestationStatementInternalResult(
            AttestationTypeEnum.Basic,
            new[] { (X509Certificate2)null! });

        // Act
        var result = _sut.Validate(attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }
}
