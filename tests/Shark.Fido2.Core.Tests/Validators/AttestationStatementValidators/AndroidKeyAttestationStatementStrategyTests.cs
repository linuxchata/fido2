using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Constants;
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
internal class AndroidKeyAttestationStatementStrategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;
    private AttestationObjectHandler _attestationObjectHandler = null!;
    private AuthenticatorDataParserService _provider = null!;
    private PublicKeyCredentialCreationOptions _creationOptions = null!;

    private AndroidKeyAttestationStatementStrategy _sut = null!;

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

        _provider = new AuthenticatorDataParserService();

        _creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        _attestationObjectHandler = new AttestationObjectHandler(
            _provider, _attestationObjectValidatorMock.Object);

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

        var certificatePublicKeyValidator = new CertificatePublicKeyValidator();

        _sut = new AndroidKeyAttestationStatementStrategy(
            signatureAttestationStatementValidator,
            attestationCertificateProviderService,
            attestationCertificateValidator,
            certificatePublicKeyValidator);
    }

    [Test]
    public async Task Validate_WhenAttestationWithEs256Algorithm_ThenReturnsValidResult()
    {
        // Arrange
        var fileName = "AndroidKeyAttestationWithEs256Algorithm.json";
        var attestationResponseData = AttestationResponseDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationResponseData!.ClientDataJson);

        var internalResult = await _attestationObjectHandler.Handle(
            attestationResponseData!.AttestationObject, clientData, _creationOptions);

        // Act
        var validatorInternalResult = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        var result = validatorInternalResult as AttestationStatementInternalResult;
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.AttestationStatementFormat, Is.EqualTo(AttestationStatementFormatIdentifier.AndroidKey));
        Assert.That(result.AttestationType, Is.EqualTo(AttestationType.Basic));
        Assert.That(result.TrustPath!.Length, Is.EqualTo(2));
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
    public void Validate_WhenAttestationStatementIsNotDictionary_ThenThrowsArgumentException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData { AttestationStatement = "Not a dictionary" };
        var clientData = ClientDataBuilder.BuildCreate();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(attestationObjectData, clientData));
    }
}
