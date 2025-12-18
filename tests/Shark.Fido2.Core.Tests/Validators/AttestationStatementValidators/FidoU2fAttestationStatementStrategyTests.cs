using Microsoft.Extensions.Logging.Abstractions;
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
internal class FidoU2FAttestationStatementStrategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;
    private AttestationObjectHandler _attestationObjectHandler = null!;
    private AuthenticatorDataParserService _provider = null!;
    private PublicKeyCredentialCreationOptions _creationOptions = null!;

    private FidoU2FAttestationStatementStrategy _sut = null!;

    [SetUp]
    public void Setup()
    {
        _attestationObjectValidatorMock = new Mock<IAttestationObjectValidator>();
        _attestationObjectValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AttestationObjectData>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>(),
                CancellationToken.None))
            .ReturnsAsync(ValidatorInternalResult.Valid());

        _provider = new AuthenticatorDataParserService();

        _creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        _attestationObjectHandler = new AttestationObjectHandler(
            _provider, _attestationObjectValidatorMock.Object, NullLogger<AttestationObjectHandler>.Instance);

        var attestationCertificateProviderService = new AttestationCertificateProviderService();

        var attestationCertificateValidator = new AttestationCertificateValidator(
            new SubjectAlternativeNameParserService(),
            new AndroidKeyAttestationExtensionParserService(),
            new AppleAnonymousExtensionParserService(),
            Options.Create(Fido2ConfigurationBuilder.Build()));

        var signatureAttestationStatementValidator = new SignatureAttestationStatementValidator(
            new RsaCryptographyValidator(),
            new Ec2CryptographyValidator(),
            new OkpCryptographyValidator());

        _sut = new FidoU2FAttestationStatementStrategy(
            attestationCertificateProviderService,
            attestationCertificateValidator,
            signatureAttestationStatementValidator,
            NullLogger<FidoU2FAttestationStatementStrategy>.Instance);
    }

    [Test]
    public async Task Validate_WhenAttestationWithEs256Algorithm_ThenReturnsValidResult()
    {
        // Arrange
        var fileName = "FidoU2fAttestationWithEs256Algorithm.json";
        var attestationResponseData = AttestationResponseDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationResponseData!.ClientDataJson);

        var internalResult = await _attestationObjectHandler.Handle(
            attestationResponseData!.AttestationObject, clientData, _creationOptions, CancellationToken.None);

        // Act
        var validatorInternalResult = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        var result = validatorInternalResult as AttestationStatementInternalResult;
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.AttestationStatementFormat, Is.EqualTo(AttestationStatementFormatIdentifier.FidoU2F));
        Assert.That(result.AttestationType, Is.EqualTo(AttestationType.AttCA));
        Assert.That(result.TrustPath!.Length, Is.EqualTo(1));
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
    public void Validate_WhenAttestationStatementIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData { AttestationStatement = null! };
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

    [Test]
    public void Validate_WhenClientDataIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatement = new Dictionary<string, object>(),
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(attestationObjectData, null!));
    }
}
