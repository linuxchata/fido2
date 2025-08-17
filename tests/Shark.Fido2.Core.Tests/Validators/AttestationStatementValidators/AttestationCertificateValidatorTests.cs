using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Tpm;
using Shark.Fido2.Tests.Common.DataReaders;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
internal class AttestationCertificateValidatorTests
{
    private AttestationObjectData _attestationObjectData;
    private ClientData _clientData;
    private byte[] _nonce;
    private Fido2Configuration _fido2Configuration;

    private Mock<ISubjectAlternativeNameParserService> _subjectAlternativeNameParserServiceMock;
    private Mock<IAndroidKeyAttestationExtensionParserService> _androidKeyAttestationExtensionParserService;
    private Mock<IAppleAnonymousExtensionParserService> _appleAnonymousExtensionParserServiceMock;

    private AttestationCertificateValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                AttestedCredentialData = new AttestedCredentialData
                {
                    CredentialId = [1, 2, 3, 4],
                    CredentialPublicKey = new CredentialPublicKey
                    {
                        KeyType = 2, // EC2
                        Algorithm = -7, // ES256
                        Curve = 1, // P-256
                        XCoordinate = [5, 6, 7, 8],
                        YCoordinate = [9, 10, 11, 12],
                    },
                    AaGuid = Guid.Parse("42383245-4437-3343-3846-423445354132"),
                },
                SignCount = 1,
            },
        };

        _clientData = new ClientData
        {
            Type = "webauthn.create",
            Challenge = "Challenge",
            Origin = "https://example.com",
            CrossOrigin = false,
            TokenBinding = null,
            ClientDataHash = [7],
        };

        _nonce = Convert.FromBase64String("XNudkHNARVtjc+Z1K3P8NoRTYCIV+uq7fBZfC62sB8w=");

        _subjectAlternativeNameParserServiceMock = new Mock<ISubjectAlternativeNameParserService>();
        _subjectAlternativeNameParserServiceMock
            .Setup(x => x.Parse(It.IsAny<X509SubjectAlternativeNameExtension>()))
            .Returns(new TpmIssuer
            {
                Manufacturer = "id:53544D20", // STMicroelectronics
                ManufacturerValue = "53544D20",
                Model = "ST33HTPHAHD8",
                Version = "id:00010102",
            });

        _androidKeyAttestationExtensionParserService = new Mock<IAndroidKeyAttestationExtensionParserService>();

        _appleAnonymousExtensionParserServiceMock = new Mock<IAppleAnonymousExtensionParserService>();

        var fakeTimeProvider = new FakeTimeProvider();
        _fido2Configuration = Fido2ConfigurationBuilder.Build();

        _sut = new AttestationCertificateValidator(
            _subjectAlternativeNameParserServiceMock.Object,
            _androidKeyAttestationExtensionParserService.Object,
            _appleAnonymousExtensionParserServiceMock.Object,
            fakeTimeProvider,
            Options.Create(_fido2Configuration));
    }

    [Test]
    public void ValidatePacked_WhenCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidatePacked(null!, _attestationObjectData));
    }

    [Test]
    public void ValidatePacked_WhenAttestationObjectDataIsNull_ThenThrowsArgumentNullException()
    {
        var certificates = CertificateDataReader.Read("Packed.pem");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidatePacked(certificates[0], null!));
    }

    [Test]
    public void ValidatePacked_WhenCertificateHasInvalidSubject_ThenReturnsInvalidResult()
    {
        // Arrange
        _attestationObjectData.AuthenticatorData!.AttestedCredentialData.AaGuid = Guid.Parse("42383245-4437-3343-3846-423445354132");

        var certificates = CertificateDataReader.Read("Tpm.pem");

        // Act
        var result = _sut.ValidatePacked(certificates[0], _attestationObjectData!);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Packed attestation statement certificate subject is invalid"));
    }

    [Test]
    public void ValidatePacked_WhenCertificateIsValidAndAaGuidMismatch_ThenReturnsValidResult()
    {
        // Arrange
        _attestationObjectData.AuthenticatorData!.AttestedCredentialData.AaGuid = Guid.NewGuid();

        var certificates = CertificateDataReader.Read("Packed.pem");

        // Act
        var result = _sut.ValidatePacked(certificates[0], _attestationObjectData!);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Packed attestation statement AAGUID mismatch"));
    }

    [Test]
    public void ValidatePacked_WhenCertificateIsValid_ThenReturnsValidResult()
    {
        // Arrange
        _attestationObjectData.AuthenticatorData!.AttestedCredentialData.AaGuid = Guid.Parse("42383245-4437-3343-3846-423445354132");

        var certificates = CertificateDataReader.Read("Packed.pem");

        // Act
        var result = _sut.ValidatePacked(certificates[0], _attestationObjectData!);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateTpm_WhenCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateTpm(null!, _attestationObjectData));
    }

    [Test]
    public void ValidateTpm_WhenAttestationObjectDataIsNull_ThenThrowsArgumentNullException()
    {
        var certificates = CertificateDataReader.Read("Tpm.pem");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateTpm(certificates[0], null!));
    }

    [Test]
    public void ValidateTpm_WhenCertificateHasEmptySubject_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Packed.pem");

        // Act
        var result = _sut.ValidateTpm(certificates[0], _attestationObjectData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("TPM attestation statement certificate has not empty subject"));
    }

    [Test]
    public void ValidateTpm_WhenCertificateIsValidAndTpmIssuerIsUnknown_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        _subjectAlternativeNameParserServiceMock
            .Setup(x => x.Parse(It.IsAny<X509SubjectAlternativeNameExtension>()))
            .Returns(new TpmIssuer
            {
                Manufacturer = "id:12345D67",
                ManufacturerValue = "12345D67",
                Model = "AA77HTPDAYD9",
                Version = "id:00000001",
            });

        // Act
        var result = _sut.ValidateTpm(certificates[0], _attestationObjectData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("TPM attestation statement certificate subject alternative name has invalid TMP manufacturer 12345D67"));
    }

    [Test]
    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void ValidateTpm_WhenCertificateIsValidAndTpmIssuerHasInvalidModel_ThenReturnsInvalidResult(string? model)
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        _subjectAlternativeNameParserServiceMock
            .Setup(x => x.Parse(It.IsAny<X509SubjectAlternativeNameExtension>()))
            .Returns(new TpmIssuer
            {
                Manufacturer = "id:53544D20", // STMicroelectronics
                ManufacturerValue = "53544D20",
                Model = model,
                Version = "id:00010102",
            });

        // Act
        var result = _sut.ValidateTpm(certificates[0], _attestationObjectData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("TPM attestation statement certificate subject alternative name has invalid model"));
    }

    [Test]
    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void ValidateTpm_WhenCertificateIsValidAndTpmIssuerHasInvalidVersion_ThenReturnsInvalidResult(string? version)
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        _subjectAlternativeNameParserServiceMock
            .Setup(x => x.Parse(It.IsAny<X509SubjectAlternativeNameExtension>()))
            .Returns(new TpmIssuer
            {
                Manufacturer = "id:53544D20", // STMicroelectronics
                ManufacturerValue = "53544D20",
                Model = "ST33HTPHAHD8",
                Version = version,
            });

        // Act
        var result = _sut.ValidateTpm(certificates[0], _attestationObjectData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("TPM attestation statement certificate subject alternative name has invalid version"));
    }

    [Test]
    public void ValidateTpm_WhenCertificateIsValidAndTpmIssuerIsKnown_ThenReturnsValidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        // Act
        var result = _sut.ValidateTpm(certificates[0], _attestationObjectData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateAndroidKey_WhenCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateAndroidKey(null!, _clientData));
    }

    [Test]
    public void ValidateAndroidKey_WhenClientDataIsNull_ThenThrowsArgumentNullException()
    {
        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateAndroidKey(certificates[0], null!));
    }

    [Test]
    public void ValidateAndroidKey_WhenCertificateIsValidAndAndroidKeyAttestationIsNotFound_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android Key attestation statement certificate 1.3.6.1.4.1.11129.2.1.17 extension is not found"));
    }

    [Test]
    public void ValidateAndroidKey_WhenCertificateIsValidAndAndroidKeyAttestationIsInvalid_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android Key attestation statement certificate 1.3.6.1.4.1.11129.2.1.17 extension is invalid"));
    }

    [Test]
    public void ValidateAndroidKey_WhenCertificateIsValidAndAttestationChallengeIsInvalid_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        _androidKeyAttestationExtensionParserService
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(new AndroidKeyAttestation
            {
                SoftwareEnforced = new AndroidKeyAuthorizationList
                {
                    IsAllApplicationsPresent = false,
                },
                HardwareEnforced = new AndroidKeyAuthorizationList
                {
                    IsAllApplicationsPresent = false,
                },
            });

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android Key attestation statement certificate attestation challenge has unexpected value"));
    }

    [Test]
    [TestCase(false, true)]
    [TestCase(true, false)]
    public void ValidateAndroidKey_WhenCertificateIsValidAndIsAllApplicationsPresentIsTrue_ThenReturnsInvalidResult(
        bool softwareEnforcedIsAllApplicationsPresent,
        bool hardwareEnforcedIsAllApplicationsPresent)
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        _androidKeyAttestationExtensionParserService
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(new AndroidKeyAttestation
            {
                SoftwareEnforced = new AndroidKeyAuthorizationList
                {
                    IsAllApplicationsPresent = softwareEnforcedIsAllApplicationsPresent,
                },
                HardwareEnforced = new AndroidKeyAuthorizationList
                {
                    IsAllApplicationsPresent = hardwareEnforcedIsAllApplicationsPresent,
                },
                AttestationChallenge = [7],
            });

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android Key attestation statement certificate all applications field is present"));
    }

    [Test]
    public void ValidateAndroidKey_WhenCertificateIsValidAndTrustedEnvironmentAndOriginIsInvalid_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        _androidKeyAttestationExtensionParserService
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(new AndroidKeyAttestation
            {
                SoftwareEnforced = new AndroidKeyAuthorizationList
                {
                },
                HardwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = 2,
                    IsAllApplicationsPresent = false,
                    Origin = -1,
                },
                AttestationChallenge = [7],
            });

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android Key attestation statement certificate hardware origin field has unexpected value"));
    }

    [Test]
    public void ValidateAndroidKey_WhenCertificateIsValidAndTrustedEnvironmentAndPurposeIsInvalid_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        _androidKeyAttestationExtensionParserService
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(new AndroidKeyAttestation
            {
                SoftwareEnforced = new AndroidKeyAuthorizationList
                {
                },
                HardwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = 1,
                    IsAllApplicationsPresent = false,
                    Origin = 0,
                },
                AttestationChallenge = [7],
            });

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android Key attestation statement certificate hardware purpose field has unexpected value"));
    }

    [Test]
    public void ValidateAndroidKey_WhenCertificateIsValidAndTrustedEnvironment_ThenReturnsValidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        _androidKeyAttestationExtensionParserService
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(new AndroidKeyAttestation
            {
                SoftwareEnforced = new AndroidKeyAuthorizationList
                {
                },
                HardwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = 2,
                    IsAllApplicationsPresent = false,
                    Origin = 0,
                },
                AttestationChallenge = [7],
            });

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    [TestCase(0, 1)]
    [TestCase(1, 0)]
    public void ValidateAndroidKey_WhenCertificateIsValidAndNotTrustedEnvironmentAndOriginIsInvalid_ThenReturnsInvalidResult(
        int softwareEnforcedOrigin,
        int hardwareEnforcedOrigin)
    {
        // Arrange
        _fido2Configuration.EnableTrustedExecutionEnvironmentOnly = false;

        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        _androidKeyAttestationExtensionParserService
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(new AndroidKeyAttestation
            {
                SoftwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = 2,
                    IsAllApplicationsPresent = false,
                    Origin = softwareEnforcedOrigin,
                },
                HardwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = 2,
                    IsAllApplicationsPresent = false,
                    Origin = hardwareEnforcedOrigin,
                },
                AttestationChallenge = [7],
            });

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android Key attestation statement certificate origin field has unexpected value"));
    }

    [Test]
    [TestCase(0, 2)]
    [TestCase(2, 0)]
    public void ValidateAndroidKey_WhenCertificateIsValidAndNotTrustedEnvironmentAndPurposeIsInvalid_ThenReturnsInvalidResult(
        int softwareEnforcedPurpose,
        int hardwareEnforcedPurpose)
    {
        // Arrange
        _fido2Configuration.EnableTrustedExecutionEnvironmentOnly = false;

        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        _androidKeyAttestationExtensionParserService
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(new AndroidKeyAttestation
            {
                SoftwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = softwareEnforcedPurpose,
                    IsAllApplicationsPresent = false,
                    Origin = 0,
                },
                HardwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = hardwareEnforcedPurpose,
                    IsAllApplicationsPresent = false,
                    Origin = 0,
                },
                AttestationChallenge = [7],
            });

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android Key attestation statement certificate purpose field has unexpected value"));
    }

    [Test]
    public void ValidateAndroidKey_WhenCertificateIsValidAndNotTrustedEnvironment_ThenReturnsValidResult()
    {
        // Arrange
        _fido2Configuration.EnableTrustedExecutionEnvironmentOnly = false;

        var certificates = CertificateDataReader.Read("AndroidKey.pem");

        _androidKeyAttestationExtensionParserService
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(new AndroidKeyAttestation
            {
                SoftwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = 2,
                    IsAllApplicationsPresent = false,
                    Origin = 0,
                },
                HardwareEnforced = new AndroidKeyAuthorizationList
                {
                    Purpose = 2,
                    IsAllApplicationsPresent = false,
                    Origin = 0,
                },
                AttestationChallenge = [7],
            });

        // Act
        var result = _sut.ValidateAndroidKey(certificates[0], _clientData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateAndroidSafetyNet_WhenCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateAndroidSafetyNet(null!));
    }

    [Test]
    public void ValidateAndroidSafetyNet_WhenCertificateHasInvalidHostName_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        // Act
        var result = _sut.ValidateAndroidSafetyNet(certificates[0]);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement certificate hostname is invalid"));
    }

    [Test]
    public void ValidateAndroidSafetyNet_WhenCertificateIsValid_ThenReturnsValidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AndroidSafetyNet.pem");

        // Act
        var result = _sut.ValidateAndroidSafetyNet(certificates[0]);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateFidoU2F_WhenCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateFidoU2F(null!));
    }

    [Test]
    public void ValidateFidoU2F_WhenCertificateIsValid_ThenReturnsValidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("FidoU2f.pem");

        // Act
        var result = _sut.ValidateFidoU2F(certificates[0]);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateFidoU2F_WhenCertificateIsNotEllipticCurveCertificate_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        // Act
        var result = _sut.ValidateFidoU2F(certificates[0]);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("FIDO U2F attestation statement certificate public key is not an Elliptic Curve (EC) public key"));
    }

    [Test]
    public void ValidateAppleAnonymous_WhenCertificateIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.ValidateAppleAnonymous(null!, _nonce));
    }

    [Test]
    public void ValidateAppleAnonymous_WhenCertificateExtensionIsNotFound_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("Tpm.pem");

        _appleAnonymousExtensionParserServiceMock
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(_nonce);

        // Act
        var result = _sut.ValidateAppleAnonymous(certificates[0], _nonce);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Apple Anonymous attestation statement certificate 1.2.840.113635.100.8.2 extension is not found"));
    }

    [Test]
    public void ValidateAppleAnonymous_WhenCertificateIsValidAndNonceIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AppleAnonymous.pem");

        // Act
        var result = _sut.ValidateAppleAnonymous(certificates[0], null!);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Apple Anonymous attestation statement certificate 1.2.840.113635.100.8.2 extension mismatch"));
    }

    [Test]
    public void ValidateAppleAnonymous_WhenCertificateIsValidAndNonceMismatch_ThenReturnsInvalidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AppleAnonymous.pem");

        var certificateNonce = Convert.FromBase64String("XNud");

        _appleAnonymousExtensionParserServiceMock
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(certificateNonce);

        // Act
        var result = _sut.ValidateAppleAnonymous(certificates[0], _nonce);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Apple Anonymous attestation statement certificate 1.2.840.113635.100.8.2 extension mismatch"));
    }

    [Test]
    public void ValidateAppleAnonymous_WhenCertificateIsValidAndNoncesMatch_ThenReturnsValidResult()
    {
        // Arrange
        var certificates = CertificateDataReader.Read("AppleAnonymous.pem");

        _appleAnonymousExtensionParserServiceMock
            .Setup(x => x.Parse(It.IsAny<byte[]>()))
            .Returns(_nonce);

        // Act
        var result = _sut.ValidateAppleAnonymous(certificates[0], _nonce);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}
