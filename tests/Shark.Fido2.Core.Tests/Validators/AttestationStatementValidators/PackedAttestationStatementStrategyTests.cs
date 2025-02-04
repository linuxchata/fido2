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
public class PackedAttestationStatementStrategyTests
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

        var subjectAlternativeNameParserService = new SubjectAlternativeNameParserService();
        var certificateAttestationStatementValidator = new CertificateAttestationStatementValidator(
            subjectAlternativeNameParserService);

        _sut = new PackedAttestationStatementStrategy(
            algorithmAttestationStatementValidator,
            signatureAttestationStatementValidator,
            certificateAttestationStatementProvider,
            certificateAttestationStatementValidator);
    }

    [Test]
    public void Validate_WhenWindowsAtenticatorWithRs256Algorithm_ShouldValidate()
    {
        // Arrange
        var attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQClP2a8p8lm+FUiGJAUj76ThUfAVUUWut6EVWUdZvC4/HBxyOCh3sZ15o+CgW4TA1dPYZpYJAx1f7AdK5JXJ7MEpgmIuVWTNklGSyWBI5FJWDgGg0LDzDFZqDuGFbupXPzWT9PP4/yBTOcAQ2ZM6YMe7o7ix95Ke9PZnyQ30oySbVyUINCQZTZucBJh9cGfb92na5I2iNEfd7JN80ea3g58xBjEol+jLAmkfPabTVa4PDuI3B7PtjV2AbpmFjB3yfq+PpScSTObjx9EqZ3EsSvEZHAfj9LwhMbEkBzDEfUxHt6xW9Vgqn32aV7VAKdkohTh5CUZNGFIC2CvKjeqFBWWaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIHgppX3fEq9YSztHkiwb17ns0+Px0i+cSd9aTkm1JD5LpAEDAzkBACBZAQCmBcYvuGi9gyjh5lXY0wiL0oYw1voBr5XHTwP+14ezQBR90zV93anRBAfqFr5MLzY+0EB+YhwjvhL51G0INgmFS6rUhpfG1wQp+MvSU7tSaK1MwZKB35r17oU77/zjroBt780iDHGdYaUx4UN0Mi4oIGe9pmZTTiSUOwq9KpoE4aixjVQNfurWUs036xnkFJ5ZMVON4ki8dXLuOtqgtNy06/X98EKsFcwNKA83ob6XKUZCnG2GlWQJyMBnE8p1p4k46r3DF5p6vdVH+3Ibujmcxhw/f6/M6UTvhvYofT+ljqFYhHKT2iRp1m2+iFQJAbcGCvXW9AWVWeqU1tBQ5yENIUMBAAE=";

        var clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZ3NqSlRqZzNyY21sM2NmRUx3eEF4USIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9";
        var clientData = GetClientData(clientDataJson);

        var internalResult = _attestationObjectHandler.Handle(attestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData, _creationOptions);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.Self));
    }

    [Test]
    public void Validate_WhenAtenticatorWithEs256Algorithm_ShouldValidate()
    {
        // Arrange
        // Source https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#packed-attestation
        // The following changes were done: - => +; _ => /; = was added
        var attestationObject = "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";

        var clientDataJson = "eyJjaGFsbGVuZ2UiOiJ1Vlg4OElnUmEwU1NyTUlSVF9xN2NSY2RmZ2ZSQnhDZ25fcGtwVUFuWEpLMnpPYjMwN3dkMU9MWFEwQXVOYU10QlIzYW1rNkhZenAtX1Z4SlRQcHdHdyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidG9rZW5CaW5kaW5nIjp7InN0YXR1cyI6Im5vdC1zdXBwb3J0ZWQifSwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9";
        var clientData = GetClientData(clientDataJson);

        var internalResult = _attestationObjectHandler.Handle(attestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData, _creationOptions);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.AttCA));
    }

    private static ClientData GetClientData(string clientDataJson)
    {
        return new ClientData
        {
            ClientDataHash = HashProvider.GetSha256Hash(Convert.FromBase64String(clientDataJson)),
        };
    }
}
