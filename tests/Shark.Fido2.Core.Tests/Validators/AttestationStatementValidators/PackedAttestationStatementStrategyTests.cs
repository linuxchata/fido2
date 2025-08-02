using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Tests.DataReaders;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
internal class PackedAttestationStatementStrategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;
    private AttestationObjectHandler _attestationObjectHandler = null!;
    private AuthenticatorDataParserService _authenticatorDataProvider = null!;
    private PublicKeyCredentialCreationOptions _creationOptions = null!;

    private PackedAttestationStatementStrategy _sut = null!;

    [SetUp]
    public void Setup()
    {
        _attestationObjectValidatorMock = new Mock<IAttestationObjectValidator>();
        _attestationObjectValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AttestationObjectData>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>()))
        .ReturnsAsync(ValidatorInternalResult.Valid());

        _authenticatorDataProvider = new AuthenticatorDataParserService();

        _creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        _attestationObjectHandler = new AttestationObjectHandler(
            _authenticatorDataProvider,
            _attestationObjectValidatorMock.Object);

        var signatureAttestationStatementValidator = new SignatureAttestationStatementValidator(
            new RsaCryptographyValidator(),
            new Ec2CryptographyValidator(),
            new OkpCryptographyValidator());

        var attestationCertificateProviderService = new AttestationCertificateProviderService();

        var attestationCertificateValidator = new AttestationCertificateValidator(
            new SubjectAlternativeNameParserService(),
            new AndroidKeyAttestationExtensionParserService(),
            new AppleAnonymousExtensionParserService(),
            TimeProvider.System,
            Options.Create(Fido2ConfigurationBuilder.Build()));

        _sut = new PackedAttestationStatementStrategy(
            signatureAttestationStatementValidator,
            attestationCertificateProviderService,
            attestationCertificateValidator);
    }

    [Test]
    public async Task Validate_WhenPackedAttestationWithRs256Algorithm_ThenValidates()
    {
        // Arrange
        var fileName = "PackedAttestationWithRs256Algorithm.json";
        var attestationResponseData = AttestationResponseDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationResponseData!.ClientDataJson);

        var internalResult = await _attestationObjectHandler.Handle(
            attestationResponseData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult, Is.Not.Null, result.Message);
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationType.Self));
    }

    [Test]
    public async Task Validate_WhenPackedAttestationWithEc2Algorithm_ThenValidates()
    {
        // Arrange
        // Source https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#packed-attestation
        var fileName = "PackedAttestationWithEc2Algorithm.json";
        var attestationResponseData = AttestationResponseDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationResponseData!.ClientDataJson);

        var internalResult = await _attestationObjectHandler.Handle(
            attestationResponseData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Trust path contains a root certificate"));
    }

    [Test]
    public async Task Validate_WhenPackedAttestationWithOkpAlgorithm_ThenValidates()
    {
        // Arrange
        var fileName = "PackedAttestationWithOkpAlgorithm.json";
        var attestationResponseData = AttestationResponseDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationResponseData!.ClientDataJson);

        var internalResult = await _attestationObjectHandler.Handle(
            attestationResponseData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult, Is.Not.Null, result.Message);
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationType.Self));
    }

    [Test]
    public void Validate_WhenAttestationObjectDataIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var clientData = ClientDataBuilder.BuildCreate();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(null!, clientData));
    }

    [Test]
    public void Validate_WhenClientDataIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(attestationObjectData, null!));
    }

    [Test]
    public void Validate_WhenAttestationStatementIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData { AttestationStatement = null };
        var clientData = ClientDataBuilder.BuildCreate();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(attestationObjectData, clientData));
    }

    [Test]
    public void Validate_WhenAttestationStatementIsNotDictionary_ThenThrowsArgumentException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData { AttestationStatement = "not a dictionary" };
        var clientData = ClientDataBuilder.BuildCreate();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(attestationObjectData, clientData));
    }
}
