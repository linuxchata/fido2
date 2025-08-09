using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Tests.DataReaders;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class AttestationTrustworthinessValidatorTests
{
    private Mock<IAttestationTrustAnchorValidator> _attestationTrustAnchorValidatorMock = null!;

    private AuthenticatorData _authenticatorData;
    private Fido2Configuration _configuration;

    private AttestationTrustworthinessValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _attestationTrustAnchorValidatorMock = new Mock<IAttestationTrustAnchorValidator>();
        _attestationTrustAnchorValidatorMock
            .Setup(a => a.ValidateBasicAttestation(It.IsAny<AuthenticatorData>(), It.IsAny<X509Certificate2[]>()))
            .ReturnsAsync(ValidatorInternalResult.Valid());

        _authenticatorData = new AuthenticatorData
        {
            AttestedCredentialData = new AttestedCredentialData(),
        };

        _configuration = Fido2ConfigurationBuilder.Build();
        var options = Options.Create(_configuration);

        _sut = new AttestationTrustworthinessValidator(
            _attestationTrustAnchorValidatorMock.Object,
            TimeProvider.System,
            options);
    }

    [Test]
    public async Task Validate_WhenAttestationStatementResultIsNull_ThenReturnsInvalid()
    {
        // Act
        var result = await _sut.Validate(_authenticatorData, null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation statement result cannot be null"));
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task Validate_WhenNoneAttestation_ThenReturnsExpectedResult(bool allowNoneAttestation)
    {
        // Arrange
        _configuration.AllowNoneAttestation = allowNoneAttestation;
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.None,
            AttestationType.None);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.EqualTo(allowNoneAttestation));
        if (!allowNoneAttestation)
        {
            Assert.That(result.Message, Is.EqualTo("None attestation type is not allowed under current policy"));
        }
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task Validate_WhenSelfAttestation_ThenReturnsExpectedResult(bool allowSelfAttestation)
    {
        // Arrange
        _configuration.AllowSelfAttestation = allowSelfAttestation;
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationType.Self);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.EqualTo(allowSelfAttestation));
        if (!allowSelfAttestation)
        {
            Assert.That(result.Message, Is.EqualTo("Self attestation type is not allowed under current policy"));
        }
    }

    [Test]
    public async Task Validate_WhenBasicAttestationWithoutTrustPath_ThenReturnsInvalid()
    {
        // Arrange
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationType.Basic);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Trust path is required for Basic attestation type"));
    }

    [Test]
    public async Task Validate_WhenBasicAttestationWithNullTrustPath_ThenReturnsInvalid()
    {
        // Arrange
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.None,
            AttestationType.Basic,
            null!);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Trust path is required for Basic attestation type"));
    }

    [Test]
    public async Task Validate_WhenBasicAttestationWithEmptyTrustPath_ThenReturnsInvalid()
    {
        // Arrange
        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.None,
            AttestationType.Basic,
            []);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Trust path is required for Basic attestation type"));
    }

    [Test]
    public async Task Validate_WhenBasicAttestationWithTrustPathWitAndroidKeyCertificates_ThenReturnsValid()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.AndroidKey,
            AttestationType.Basic,
            certificates);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenBasicSurrogateAttestationWithTrustPathWithPackedCertificates_ThenReturnsInvalid()
    {
        // Arrange
        var errorMessage = $"basic_surrogate (self) attestation type cannot have trust path";

        _attestationTrustAnchorValidatorMock
            .Setup(a => a.ValidateBasicAttestation(It.IsAny<AuthenticatorData>(), It.IsAny<X509Certificate2[]>()))
            .ReturnsAsync(ValidatorInternalResult.Invalid(errorMessage));

        var certificates = CertificateDataReader.Read("Packed.pem");

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationType.AttCA,
            certificates);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo(errorMessage));
    }

    [Test]
    public async Task Validate_WhenAnonCaAttestationWithTrustPathWithAppleAnonymousCertificates_ThenReturnsValid()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AppleAnonymous.pem");

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Apple,
            AttestationType.AnonCA,
            certificates);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file."));
    }

    [Test]
    public async Task Validate_WhenAttCaAttestationWithTrustPathWithTpmCertificates_ThenReturnsValid()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Tpm,
            AttestationType.AttCA,
            certificates);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenAttCaAttestationWithTrustPathWithPackedCertificates_ThenReturnsValid()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Packed.pem");

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationType.AttCA,
            certificates);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenAttCaAttestationWithTrustPathWithPackedCertificatesWithCa_ThenReturnsValid()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("PackedWithCa.pem");

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.Packed,
            AttestationType.AttCA,
            certificates);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenAttCaAttestationWithTrustPathWitFidoU2fCertificates_ThenReturnsValid()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("FidoU2f.pem");

        var attestationResult = new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.FidoU2F,
            AttestationType.AttCA,
            certificates);

        // Act
        var result = await _sut.Validate(_authenticatorData, attestationResult);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}
