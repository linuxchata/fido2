using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class AttestationObjectValidatorTests
{
    private const string Packed = AttestationStatementFormatIdentifier.Packed;

    private AttestationObjectData _attestationObjectData;

    private Mock<IAttestationStatementValidator> _attestationStatementValidatorMock;
    private Mock<IAttestationTrustworthinessValidator> _attestationTrustworthinessValidatorMock;
    private Mock<IAttestationTrustAnchorValidator> _attestationTrustAnchorValidatorMock;

    private AttestationObjectValidator _sut;

    [SetUp]
    public void Setup()
    {
        _attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = Convert.FromBase64String("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2M="),
                AttestedCredentialData = new AttestedCredentialData
                {
                    CredentialPublicKey = new CredentialPublicKey
                    {
                        Algorithm = (int)CoseAlgorithm.Rs256,
                    },
                },
                UserPresent = true,
                UserVerified = true,
            },
            AttestationStatementFormat = Packed,
        };

        _attestationStatementValidatorMock = new Mock<IAttestationStatementValidator>();
        _attestationStatementValidatorMock
            .Setup(a => a.Validate(It.IsAny<AttestationObjectData>(), It.IsAny<ClientData>()))
            .Returns(new AttestationStatementInternalResult(Packed, AttestationType.Basic));

        _attestationTrustworthinessValidatorMock = new Mock<IAttestationTrustworthinessValidator>();
        _attestationTrustworthinessValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AuthenticatorData>(),
                It.IsAny<AttestationStatementInternalResult>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidatorInternalResult.Valid());

        _attestationTrustAnchorValidatorMock = new Mock<IAttestationTrustAnchorValidator>();
        _attestationTrustAnchorValidatorMock
            .Setup(a => a.Validate(It.IsAny<AuthenticatorData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidatorInternalResult.Valid());

        _sut = new AttestationObjectValidator(
            _attestationStatementValidatorMock.Object,
            _attestationTrustworthinessValidatorMock.Object,
            _attestationTrustAnchorValidatorMock.Object,
            Options.Create(Fido2ConfigurationBuilder.Build()));
    }

    [Test]
    public async Task Validate_WhenAttestationObjectDataIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        AttestationObjectData? attestationObjectData = null;

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData!, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation object cannot be null"));
    }

    [Test]
    public async Task Validate_WhenClientDataIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        ClientData? clientData = null;

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(_attestationObjectData, clientData!, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Client data cannot be null"));
    }

    [Test]
    public async Task Validate_WhenCreationOptionsIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var clientData = ClientDataBuilder.BuildCreate();

        PublicKeyCredentialCreationOptions? creationOptions = null!;

        // Act
        var result = await _sut.Validate(_attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Creation options cannot be null"));
    }

    [Test]
    public async Task Validate_WhenAuthenticatorDataIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData();

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Authenticator data cannot be null"));
    }

    [Test]
    public async Task Validate_WhenRpIdHashMismatched_ThenReturnsInvalidResult()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = [0x00, 0x01],
                AttestedCredentialData = _attestationObjectData.AuthenticatorData!.AttestedCredentialData,
                UserPresent = false,
                UserVerified = false,
            },
            AttestationStatementFormat = _attestationObjectData.AttestationStatementFormat,
        };

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("RP ID hash mismatch"));
    }

    [Test]
    public async Task Validate_WhenUserIsNotPresent_ThenReturnsInvalidResult()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = _attestationObjectData.AuthenticatorData!.RpIdHash,
                AttestedCredentialData = _attestationObjectData.AuthenticatorData!.AttestedCredentialData,
                UserPresent = false,
                UserVerified = false,
            },
            AttestationStatementFormat = _attestationObjectData.AttestationStatementFormat,
        };

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData!, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User Present bit is not set"));
    }

    [Test]
    public async Task Validate_WhenUserVerificationRequiredAndUserIsNotVerified_ThenReturnsInvalidResult()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = _attestationObjectData.AuthenticatorData!.RpIdHash,
                AttestedCredentialData = _attestationObjectData.AuthenticatorData!.AttestedCredentialData,
                UserPresent = true,
                UserVerified = false,
            },
            AttestationStatementFormat = _attestationObjectData.AttestationStatementFormat,
        };

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User Verified bit is not set as user verification is required"));
    }

    [Test]
    public async Task Validate_WhenCredentialPublicKeyIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = _attestationObjectData.AuthenticatorData!.RpIdHash,
                AttestedCredentialData = new AttestedCredentialData
                {
                    CredentialPublicKey = null,
                },
                UserPresent = true,
                UserVerified = true,
            },
            AttestationStatementFormat = _attestationObjectData.AttestationStatementFormat,
        };

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Credential public key algorithm mismatch"));
    }

    [Test]
    public async Task Validate_WhenAlgorithmMismatch_ThenReturnsInvalidResult()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = _attestationObjectData.AuthenticatorData!.RpIdHash,
                AttestedCredentialData = new AttestedCredentialData
                {
                    CredentialPublicKey = new CredentialPublicKey
                    {
                        Algorithm = (int)CoseAlgorithm.Ps384,
                    },
                },
                UserPresent = true,
                UserVerified = true,
            },
            AttestationStatementFormat = _attestationObjectData.AttestationStatementFormat,
        };

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Credential public key algorithm mismatch"));
    }

    [Test]
    public async Task Validate_WhenAttestationStatementFormatIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = _attestationObjectData.AuthenticatorData!.RpIdHash,
                AttestedCredentialData = _attestationObjectData.AuthenticatorData!.AttestedCredentialData,
                UserPresent = true,
                UserVerified = true,
            },
            AttestationStatementFormat = null,
        };

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation statement format cannot be null"));
    }

    [Test]
    public async Task Validate_WhenAttestationStatementFormatIsNotSupported_ThenReturnsInvalidResult()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = _attestationObjectData.AuthenticatorData!.RpIdHash,
                AttestedCredentialData = _attestationObjectData.AuthenticatorData!.AttestedCredentialData,
                UserPresent = true,
                UserVerified = true,
            },
            AttestationStatementFormat = "NotSupported",
        };

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation statement format [NotSupported] is not supported"));
    }

    [Test]
    public async Task Validate_WhenAttestationStatementIsInvalid_ThenReturnsInvalidResult()
    {
        // Arrange
        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        var errorMessage = "Attestation statement is invalid";
        _attestationStatementValidatorMock
            .Setup(a => a.Validate(It.IsAny<AttestationObjectData>(), It.IsAny<ClientData>()))
            .Returns(ValidatorInternalResult.Invalid(errorMessage));

        // Act
        var result = await _sut.Validate(_attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo(errorMessage));
    }

    [Test]
    public async Task Validate_WhenResultIsNotAttestationStatementInternalResult_ThenReturnsInvalidResult()
    {
        // Arrange
        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        _attestationStatementValidatorMock
            .Setup(a => a.Validate(It.IsAny<AttestationObjectData>(), It.IsAny<ClientData>()))
            .Returns(ValidatorInternalResult.Valid());

        // Act
        var result = await _sut.Validate(_attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation statement result is not of an expected type"));
    }

    [Test]
    public async Task Validate_WhenTrustAnchorValidationFails_ThenReturnsInvalidResult()
    {
        // Arrange
        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        var errorMessage = "Metadata for authenticator 9876e770-4250-4572-90a1-645d16f59463 is not available";
        _attestationTrustAnchorValidatorMock
            .Setup(a => a.Validate(It.IsAny<AuthenticatorData>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidatorInternalResult.Invalid(errorMessage));

        // Act
        var result = await _sut.Validate(_attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo(errorMessage));
    }

    [Test]
    public async Task Validate_WhenAttestationTrustworthinessValidationFails_ThenReturnsInvalidResult()
    {
        // Arrange
        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        var errorMessage = "None attestation type is not allowed under current policy";
        _attestationTrustworthinessValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AuthenticatorData>(),
                It.IsAny<AttestationStatementInternalResult>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidatorInternalResult.Invalid(errorMessage));

        // Act
        var result = await _sut.Validate(_attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo(errorMessage));
    }

    [Test]
    public async Task Validate_WhenAttestationObjectDataIsValid_ThenReturnsValidResult()
    {
        // Arrange
        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Validate(_attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    [TestCase(UserVerificationRequirement.Preferred)]
    [TestCase(UserVerificationRequirement.Discouraged)]
    public async Task Validate_WhenAttestationObjectDataIsValidAndUserVerificationIsNotRequired_ThenReturnsValidResult(
        UserVerificationRequirement userVerification)
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AuthenticatorData = new AuthenticatorData
            {
                RpIdHash = _attestationObjectData.AuthenticatorData!.RpIdHash,
                AttestedCredentialData = _attestationObjectData.AuthenticatorData!.AttestedCredentialData,
                UserPresent = true,
                UserVerified = false,
            },
            AttestationStatementFormat = Packed,
        };

        var clientData = ClientDataBuilder.BuildCreate();

        var creationOptions = BuildCreationOptions(CoseAlgorithm.Rs256, userVerification);

        // Act
        var result = await _sut.Validate(attestationObjectData, clientData, creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenPackedAttestationStatementFormatAndEs256Algorithm_ThenReturnsValidResult()
    {
        // iPhone authenticator

        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);
        var attestationObjectData = BuildAttestationObjectData(authenticatorDataArray);

        var creationOptions = BuildCreationOptions(CoseAlgorithm.Es256);

        // Act
        var result = await _sut.Validate(
            attestationObjectData,
            ClientDataBuilder.BuildCreate(),
            creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenPackedAttestationStatementFormatAndRs256Algorithm_ThenReturnsValidResult()
    {
        // Windows Hello authenticator

        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIHgppX3fEq9YSztHkiwb17ns0+Px0i+cSd9aTkm1JD5LpAEDAzkBACBZAQCmBcYvuGi9gyjh5lXY0wiL0oYw1voBr5XHTwP+14ezQBR90zV93anRBAfqFr5MLzY+0EB+YhwjvhL51G0INgmFS6rUhpfG1wQp+MvSU7tSaK1MwZKB35r17oU77/zjroBt780iDHGdYaUx4UN0Mi4oIGe9pmZTTiSUOwq9KpoE4aixjVQNfurWUs036xnkFJ5ZMVON4ki8dXLuOtqgtNy06/X98EKsFcwNKA83ob6XKUZCnG2GlWQJyMBnE8p1p4k46r3DF5p6vdVH+3Ibujmcxhw/f6/M6UTvhvYofT+ljqFYhHKT2iRp1m2+iFQJAbcGCvXW9AWVWeqU1tBQ5yENIUMBAAE=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);
        var attestationObjectData = BuildAttestationObjectData(authenticatorDataArray);

        var creationOptions = BuildCreationOptions(CoseAlgorithm.Rs256);

        // Act
        var result = await _sut.Validate(
            attestationObjectData,
            ClientDataBuilder.BuildCreate(),
            creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    private AttestationObjectData BuildAttestationObjectData(byte[] authenticatorDataArray)
    {
        var parserService = new AuthenticatorDataParserService();
        var authenticatorData = parserService.Parse(authenticatorDataArray);

        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatementFormat = AttestationStatementFormatIdentifier.Packed,
            AuthenticatorData = authenticatorData,
        };

        return attestationObjectData;
    }

    private PublicKeyCredentialCreationOptions BuildCreationOptions(
        CoseAlgorithm coseAlgorithm,
        UserVerificationRequirement userVerification = UserVerificationRequirement.Required)
    {
        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();
        creationOptions.PublicKeyCredentialParams = [new() { Algorithm = coseAlgorithm }];
        creationOptions.AuthenticatorSelection = new AuthenticatorSelectionCriteria
        {
            UserVerification = userVerification,
        };

        return creationOptions;
    }
}