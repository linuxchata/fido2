using System.Text.Json;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
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

        var algorithmAttestationStatementValidator = new AlgorithmAttestationStatementValidator();

        var signatureAttestationStatementValidator = new SignatureAttestationStatementValidator(
            new RsaCryptographyValidator(),
            new Ec2CryptographyValidator());

        var certificateAttestationStatementProvider = new CertificateAttestationStatementService();

        var certificateAttestationStatementValidator = new CertificateAttestationStatementValidator(
            new SubjectAlternativeNameParserService());

        _sut = new PackedAttestationStatementStrategy(
            algorithmAttestationStatementValidator,
            signatureAttestationStatementValidator,
            certificateAttestationStatementProvider,
            certificateAttestationStatementValidator);
    }

    [Test]
    public void ValidatePacked_WhenWindowsAuthenticatorWithRs256Algorithm_ShouldValidate()
    {
        // Arrange
        var fileName = "PackedAttestationWindowsAuthenticatorWithRs256.json";
        var attestationData = GetAttestationData(fileName);
        var clientData = GetClientData(attestationData!.ClientDataJson);

        var internalResult = _attestationObjectHandler.Handle(
            attestationData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData, _creationOptions);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult, Is.Not.Null, result.Message);
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.Self));
    }

    [Test]
    public void ValidatePacked_WhenAuthenticatorWithEs256Algorithm_ShouldValidate()
    {
        // Arrange
        // Source https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#packed-attestation
        var fileName = "PackedAttestationAuthenticatorWithEs256.json";
        var attestationData = GetAttestationData(fileName);
        var clientData = GetClientData(attestationData!.ClientDataJson);

        var internalResult = _attestationObjectHandler.Handle(
            attestationData!.AttestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData, _creationOptions!);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult, Is.Not.Null, result.Message);
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.AttCA));
    }

    private static AttestationData? GetAttestationData(string fileName)
    {
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        var testDataPath = Path.Combine(baseDirectory, "Data", fileName);
        var testData = File.ReadAllText(testDataPath);
        return JsonSerializer.Deserialize<AttestationData>(testData);
    }

    private static ClientData GetClientData(string clientDataJson)
    {
        return new ClientData
        {
            ClientDataHash = HashProvider.GetSha256Hash(Convert.FromBase64String(clientDataJson)),
        };
    }
}
