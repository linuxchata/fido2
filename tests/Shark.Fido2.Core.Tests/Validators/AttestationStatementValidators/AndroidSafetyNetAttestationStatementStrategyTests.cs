using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Tests.DataReaders;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
internal class AndroidSafetyNetAttestationStatementStrategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;
    private AttestationObjectHandler _attestationObjectHandler = null!;
    private AuthenticatorDataParserService _provider = null!;
    private PublicKeyCredentialCreationOptions _creationOptions = null!;

    private AndroidSafetyNetAttestationStatementStrategy _sut = null!;

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

        var jwsResponseParserService = new AndroidSafetyNetJwsResponseParserService();

        var fakeTimeProvider = new FakeTimeProvider();
        var jwsResponseValidator = new AndroidSafetyNetJwsResponseValidator(fakeTimeProvider);

        var attestationCertificateProviderService = new AttestationCertificateProviderService();

        var attestationCertificateValidator = new AttestationCertificateValidator(
            new SubjectAlternativeNameParserService(),
            new AndroidKeyAttestationExtensionParserService(),
            new AppleAnonymousExtensionParserService(),
            Options.Create(Fido2ConfigurationBuilder.Build()));

        _sut = new AndroidSafetyNetAttestationStatementStrategy(
            jwsResponseParserService,
            jwsResponseValidator,
            attestationCertificateProviderService,
            attestationCertificateValidator,
            NullLogger<AndroidSafetyNetAttestationStatementStrategy>.Instance);
    }

    [Test]
    public async Task Validate_WhenAttestationWithRs256AlgorithmAndInvalidCertificate_ThenReturnsInvalidResult()
    {
        // Arrange
        var fileName = "AndroidSafetyNetAttestationWithRs256Algorithm.json";
        var attestationResponseData = AttestationResponseDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationResponseData!.ClientDataJson);

        var internalResult = await _attestationObjectHandler.Handle(
            attestationResponseData!.AttestationObject, clientData, _creationOptions, CancellationToken.None);

        // Act
        var validatorInternalResult = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        Assert.That(validatorInternalResult, Is.Not.Null);
        Assert.That(validatorInternalResult.IsValid, Is.False);
        Assert.That(validatorInternalResult.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response signature is not valid"));
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
