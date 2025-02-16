using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
internal class NoneAttestationStatementStrategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock;
    private AttestationObjectHandler _attestationObjectHandler;
    private AuthenticatorDataParserService _provider;
    private PublicKeyCredentialCreationOptions _creationOptions;

    private NoneAttestationStatementStrategy _sut = null!;

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

        _provider = new AuthenticatorDataParserService();

        _creationOptions = new PublicKeyCredentialCreationOptions();

        _attestationObjectHandler = new AttestationObjectHandler(
            _provider, _attestationObjectValidatorMock.Object);

        _sut = new NoneAttestationStatementStrategy();
    }

    [Test]
    public void Validate_WhenNoneAttestation_ShouldValidate()
    {
        // Arrange
        var fileName = "NoneAttestation.json";
        var attestationData = AttestationDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationData!.ClientDataJson);

        var internalResult = _attestationObjectHandler.Handle(
            attestationData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult, Is.Not.Null, result.Message);
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.None));
    }
}
