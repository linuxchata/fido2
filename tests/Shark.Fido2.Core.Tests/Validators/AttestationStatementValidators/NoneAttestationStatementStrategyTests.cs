using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Tests.DataReaders;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
internal class NoneAttestationStatementStrategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;
    private AttestationObjectHandler _attestationObjectHandler = null!;
    private AuthenticatorDataParserService _authenticatorDataParserService = null!;
    private PublicKeyCredentialCreationOptions _creationOptions = null!;

    private NoneAttestationStatementStrategy _sut = null!;

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

        _authenticatorDataParserService = new AuthenticatorDataParserService();

        _creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        _attestationObjectHandler = new AttestationObjectHandler(
            _authenticatorDataParserService, _attestationObjectValidatorMock.Object, NullLogger<AttestationObjectHandler>.Instance);

        _sut = new NoneAttestationStatementStrategy();
    }

    [Test]
    public async Task Validate_WhenAttestationIsValid_ThenReturnsValidResult()
    {
        // Arrange
        var fileName = "NoneAttestation.json";
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
        Assert.That(result.AttestationStatementFormat, Is.EqualTo(AttestationStatementFormatIdentifier.None));
        Assert.That(result.AttestationType, Is.EqualTo(AttestationType.None));
        Assert.That(result.TrustPath, Is.Null);
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
        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatement = null!,
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(attestationObjectData, null!));
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
    public void Validate_WhenClientDataIsNull_ThenDoesThrowException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatement = new Dictionary<string, object>(),
        };

        // Act & Assert
        Assert.DoesNotThrow(() => _sut.Validate(attestationObjectData, null!));
    }
}
