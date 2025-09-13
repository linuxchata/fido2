using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Domain;
using Shark.Fido2.Tests.Common.DataReaders;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class AttestationFidoMetadataServiceValidatorTests
{
    private const string Description = nameof(Description);
    private const string FidoCertifiedStatus = "FIDO_CERTIFIED";

    private Mock<IMetadataCachedService> _metadataServiceMock = null!;

    private AuthenticatorData _authenticatorData;
    private Fido2Configuration _configuration;

    private Guid _aaGuid;
    private string _effectiveDate;
    private X509Certificate2[] _certificates;

    private AttestationFidoMetadataServiceValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _metadataServiceMock = new Mock<IMetadataCachedService>();

        _aaGuid = Guid.NewGuid();
        _authenticatorData = new AuthenticatorData
        {
            AttestedCredentialData = new AttestedCredentialData
            {
                AaGuid = _aaGuid,
            },
        };

        _effectiveDate = DateTime.UtcNow.ToString("o");

        _certificates = CertificateDataReader.Read("FidoU2f.pem");

        _configuration = Fido2ConfigurationBuilder.Build();
        _configuration.EnableMetadataService = true;
        var options = Options.Create(_configuration);

        _sut = new AttestationFidoMetadataServiceValidator(
            _metadataServiceMock.Object,
            options,
            NullLogger<AttestationFidoMetadataServiceValidator>.Instance);
    }

    [Test]
    public async Task Validate_WhenMetadataServiceIsDisabled_ThenReturnsValid()
    {
        // Arrange
        _configuration.EnableMetadataService = false;

        // Act
        var result = await _sut.Validate(_authenticatorData, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenMetadataIsFoundWithNoRisk_ThenReturnsValid()
    {
        // Arrange
        var metadataItem = new MetadataPayloadItem
        {
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = _effectiveDate },
            ],
            AttestationTypes = ["basic", "self"],
        };

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(metadataItem);

        // Act
        var result = await _sut.Validate(_authenticatorData, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenMetadataIsFoundWithIncreasedRisk_ThenReturnsInvalid()
    {
        // Arrange
        var metadataItem = new MetadataPayloadItem
        {
            Aaguid = _aaGuid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = "REVOKED", EffectiveDate = _effectiveDate },
            ],
            AttestationTypes = ["basic", "self"],
        };

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(metadataItem);

        // Act
        var result = await _sut.Validate(_authenticatorData, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo($"Authenticator {_aaGuid} has REVOKED status (increased risk)"));
    }

    [TestCase("USER_VERIFICATION_BYPASS")]
    [TestCase("ATTESTATION_KEY_COMPROMISE")]
    [TestCase("USER_KEY_REMOTE_COMPROMISE")]
    [TestCase("USER_KEY_PHYSICAL_COMPROMISE")]
    [TestCase("REVOKED")]
    public async Task Validate_WhenMetadataIsFoundWithVariousRiskStatuses_ThenReturnsInvalid(string riskStatus)
    {
        // Arrange
        var metadataItem = new MetadataPayloadItem
        {
            Aaguid = _aaGuid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = riskStatus, EffectiveDate = _effectiveDate },
            ],
            AttestationTypes = ["basic", "self"],
        };

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(metadataItem);

        // Act
        var result = await _sut.Validate(_authenticatorData, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo($"Authenticator {_aaGuid} has {riskStatus} status (increased risk)"));
    }

    [Test]
    public async Task Validate_WhenMetadataNotFoundWithStrictVerificationDisabled_ThenReturnsValid()
    {
        // Arrange
        _configuration.EnableStrictAuthenticatorVerification = false;

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MetadataPayloadItem?)null);

        // Act
        var result = await _sut.Validate(_authenticatorData, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenMetadataIsNotFoundWithStrictVerificationEnabled_ThenReturnsInvalid()
    {
        // Arrange
        _configuration.EnableStrictAuthenticatorVerification = true;

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MetadataPayloadItem?)null);

        // Act
        var result = await _sut.Validate(_authenticatorData, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo($"Metadata for authenticator {_aaGuid} is not available"));
    }

    [Test]
    public async Task ValidateBasicAttestation_WhenMetadataServiceIsDisabled_ThenReturnsValid()
    {
        // Arrange
        _configuration.EnableMetadataService = false;

        var trustPath = _certificates;

        // Act
        var result = await _sut.ValidateBasicAttestation(_authenticatorData, trustPath, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task ValidateBasicAttestation_MetadataIsNotFound_ThenReturnsValid()
    {
        // Arrange
        var trustPath = _certificates;

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MetadataPayloadItem?)null);

        // Act
        var result = await _sut.ValidateBasicAttestation(_authenticatorData, trustPath, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task ValidateBasicAttestation_MetadataIsFoundWithBasicSurrogateAndTrustPath_ThenReturnsInvalid()
    {
        // Arrange
        var trustPath = _certificates;

        var metadataItem = new MetadataPayloadItem
        {
            Aaguid = _aaGuid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = _effectiveDate },
            ],
            AttestationTypes = ["basic_surrogate"],
        };

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(metadataItem);

        // Act
        var result = await _sut.ValidateBasicAttestation(_authenticatorData, trustPath, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("basic_surrogate (self) attestation type cannot have trust path"));
    }

    [Test]
    public async Task ValidateBasicAttestation_MetadataIsFoundWithBasicSurrogateAndNoTrustPath_ThenReturnsValid()
    {
        // Arrange
        X509Certificate2[]? trustPath = null;

        var metadataItem = new MetadataPayloadItem
        {
            Aaguid = _aaGuid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = _effectiveDate },
            ],
            AttestationTypes = ["basic_surrogate"],
        };

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(metadataItem);

        // Act
        var result = await _sut.ValidateBasicAttestation(_authenticatorData, trustPath, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task ValidateBasicAttestation_MetadataIsFoundWithBasicSurrogateAndEmptyTrustPath_ThenReturnsValid()
    {
        // Arrange
        var trustPath = Array.Empty<X509Certificate2>();
        var metadataItem = new MetadataPayloadItem
        {
            Aaguid = _aaGuid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = _effectiveDate },
            ],
            AttestationTypes = ["basic_surrogate"],
        };

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(metadataItem);

        // Act
        var result = await _sut.ValidateBasicAttestation(_authenticatorData, trustPath, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task ValidateBasicAttestation_MetadataIsFoundWithMultipleAttestationTypes_ThenReturnsValid()
    {
        // Arrange
        var trustPath = _certificates;
        var metadataItem = new MetadataPayloadItem
        {
            Aaguid = _aaGuid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = _effectiveDate },
            ],
            AttestationTypes = ["basic", "basic_surrogate", "attca"],
        };

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(metadataItem);

        // Act
        var result = await _sut.ValidateBasicAttestation(_authenticatorData, trustPath, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task ValidateBasicAttestation_MetadataIsFoundWithNonBasicSurrogateAttestationType_ThenReturnsValid()
    {
        // Arrange
        var trustPath = _certificates;
        var metadataItem = new MetadataPayloadItem
        {
            Aaguid = _aaGuid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = _effectiveDate },
            ],
            AttestationTypes = ["basic", "attca"],
        };

        _metadataServiceMock
            .Setup(m => m.Get(_aaGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(metadataItem);

        // Act
        var result = await _sut.ValidateBasicAttestation(_authenticatorData, trustPath, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}