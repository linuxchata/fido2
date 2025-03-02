﻿using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Tests.DataReaders;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
internal class AndroidSafetyNetAttestationStatementStrategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock;
    private AttestationObjectHandler _attestationObjectHandler;
    private AuthenticatorDataParserService _provider;
    private PublicKeyCredentialCreationOptions _creationOptions;

    private AndroidSafetyNetAttestationStatementStrategy _sut = null!;

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

        var jwsResponseParserService = new AndroidSafetyNetJwsResponseParserService();

        var jwsResponseValidator = new AndroidSafetyNetJwsResponseValidator();

        var attestationCertificateProviderService = new AttestationCertificateProviderService();

        var attestationCertificateValidator = new AttestationCertificateValidator(
            new SubjectAlternativeNameParserService(),
            new AndroidKeyAttestationExtensionParserService(),
            new AppleAnonymousExtensionParserService());

        _sut = new AndroidSafetyNetAttestationStatementStrategy(
            jwsResponseParserService,
            jwsResponseValidator,
            attestationCertificateProviderService,
            attestationCertificateValidator);
    }

    [Test]
    public void Validate_WhenAndroidSafetyNetAttestationWithRs256Algorithm_ShouldValidate()
    {
        // Arrange
        var fileName = "AndroidSafetyNetAttestationWithRs256Algorithm.json";
        var attestationResponseData = AttestationResponseDataReader.Read(fileName);
        var clientData = ClientDataBuilder.Build(attestationResponseData!.ClientDataJson);

        var internalResult = _attestationObjectHandler.Handle(
            attestationResponseData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult, Is.Not.Null, result.Message);
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.Basic));
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
    public void Validate_WhenAttestationStatementIsNotDictionary_ThrowsArgumentException()
    {
        // Arrange
        var attestationObjectData = new AttestationObjectData { AttestationStatement = "not a dictionary" };
        var clientData = new ClientData();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(attestationObjectData, clientData));
    }
}
