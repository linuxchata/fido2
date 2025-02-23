using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
internal class PackedAttestationStatementStrategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock;
    private AttestationObjectHandler _attestationObjectHandler;
    private AuthenticatorDataParserService _authenticatorDataProvider;
    private PublicKeyCredentialCreationOptions _creationOptions;

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
        .Returns(ValidatorInternalResult.Valid());

        _authenticatorDataProvider = new AuthenticatorDataParserService();

        _creationOptions = new PublicKeyCredentialCreationOptions();

        _attestationObjectHandler = new AttestationObjectHandler(
            _authenticatorDataProvider,
            _attestationObjectValidatorMock.Object);

        var signatureAttestationStatementValidator = new SignatureAttestationStatementValidator(
            new RsaCryptographyValidator(),
            new Ec2CryptographyValidator());

        var certificateAttestationStatementProvider = new CertificateAttestationStatementService();

        var certificateAttestationStatementValidator = new CertificateAttestationStatementValidator(
            new SubjectAlternativeNameParserService(),
            new AndroidKeyAttestationExtensionParserService(),
            new AppleAnonymousExtensionParserService());

        _sut = new PackedAttestationStatementStrategy(
            signatureAttestationStatementValidator,
            certificateAttestationStatementProvider,
            certificateAttestationStatementValidator);
    }

    [Test]
    public void Validate_WhenPackedAttestationWithRs256Algorithm_ShouldValidate()
    {
        // Arrange
        var fileName = "PackedAttestationWithRs256Algorithm.json";
        var attestationData = AttestationDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationData!.ClientDataJson);

        var internalResult = _attestationObjectHandler.Handle(
            attestationData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult, Is.Not.Null, result.Message);
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.Self));
    }

    [Test]
    public void Validate_WhenPackedAttestationWithEs256Algorithm_ShouldValidate()
    {
        // Arrange
        // Source https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#packed-attestation
        var fileName = "PackedAttestationWithEs256Algorithm.json";
        var attestationData = AttestationDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationData!.ClientDataJson);

        var internalResult = _attestationObjectHandler.Handle(
            attestationData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult, Is.Not.Null, result.Message);
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.AttCA));
    }

    [Test]
    public void Validate_WhenAttestationObjectDataIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var clientData = new ClientData();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(null!, clientData));
    }

    [Test]
    public void Validate_WhenClientDataIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(attestationObjectData, null!));
    }

    [Test]
    public void Validate_WhenAttestationStatementIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData { AttestationStatement = null };
        var clientData = new ClientData();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(attestationObjectData, clientData));
    }

    [Test]
    public void Validate_WhenAttestationStatementIsNotDictionary_ThrowsArgumentException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData { AttestationStatement = "not a dictionary" };
        var clientData = new ClientData();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(attestationObjectData, clientData));
    }
}
