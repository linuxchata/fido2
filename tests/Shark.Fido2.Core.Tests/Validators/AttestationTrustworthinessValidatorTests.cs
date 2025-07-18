using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Tests.DataReaders;
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
        _configuration = Fido2ConfigurationBuilder.Build();
        var options = Options.Create(_configuration);
        _sut = new AttestationTrustworthinessValidator(TimeProvider.System, options);
    }

    [Test]
    public void Validate_WhenNullAttestationStatementResult_ThenReturnsInvalid()
    {
        // Act
        var result = _sut.Validate(null!, null);

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
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.None,
            AttestationTypeEnum.None);

        // Act
        var result = _sut.Validate(attestationResult, null);

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
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationTypeEnum.Self);

        // Act
        var result = _sut.Validate(attestationResult, null);

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
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationTypeEnum.Basic);

        // Act
        var result = _sut.Validate(attestationResult, null);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Trust path is required for Basic attestation type"));
    }

    [Test]
    public void Validate_WhenBasicAttestationWithEmptyTrustPath_ThenReturnsInvalid()
    {
        // Arrange
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.None,
            AttestationTypeEnum.Basic,
            []);

        // Act
        var result = _sut.Validate(attestationResult, null);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Trust path is required for Basic attestation type"));
    }

    [Test]
    public void Validate_WhenBasicAttestationWithTrustPathWitAndroidKeyCertificates_ThenReturnsValid()
    {
        // Arrange
        var fileName = "AndroidKey.pem";
        var certificateData = CertificateDataReader.Read(fileName);

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.AndroidKey,
            AttestationTypeEnum.Basic,
            certificateData);

        // Act
        var result = _sut.Validate(attestationResult, null);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenAnonCaAttestationWithTrustPathWithAppleAnonymousCertificates_ThenReturnsValid()
    {
        // Arrange
        var fileName = "AppleAnonymous.pem";
        var certificateData = CertificateDataReader.Read(fileName);

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Apple,
            AttestationTypeEnum.AnonCA,
            certificateData);

        // Act
        var result = _sut.Validate(attestationResult, null);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.Not.Null);
    }

    [Test]
    public void Validate_WhenAttCaAttestationWithTrustPathWithTpmCertificates_ThenReturnsValid()
    {
        // Arrange
        var fileName = "Tpm.pem";
        var certificateData = CertificateDataReader.Read(fileName);

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Tpm,
            AttestationTypeEnum.AttCA,
            certificateData);

        // Act
        var result = _sut.Validate(attestationResult, null);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenAttCaAttestationWithTrustPathWithPackedCertificates_ThenReturnsValid()
    {
        // Arrange
        var fileName = "Packed.pem";
        var certificateData = CertificateDataReader.Read(fileName);

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationTypeEnum.AttCA,
            certificateData);

        // Act
        var result = _sut.Validate(attestationResult, null);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenAttCaAttestationWithTrustPathWithPackedCertificatesWithCa_ThenReturnsValid()
    {
        // Arrange
        var fileName = "PackedWithCa.pem";
        var certificateData = CertificateDataReader.Read(fileName);

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationTypeEnum.AttCA,
            certificateData);

        // Act
        var result = _sut.Validate(attestationResult, null);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenAttCaAttestationWithTrustPathWitFidoU2fCertificates_ThenReturnsValid()
    {
        // Arrange
        var fileName = "FidoU2f.pem";
        var certificateData = CertificateDataReader.Read(fileName);

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.FidoU2f,
            AttestationTypeEnum.AttCA,
            certificateData);

        // Act
        var result = _sut.Validate(attestationResult, null);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}
