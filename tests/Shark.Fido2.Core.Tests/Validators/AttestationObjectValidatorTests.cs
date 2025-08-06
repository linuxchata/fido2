using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class AttestationObjectValidatorTests
{
    private AttestationObjectValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        var attestationStatementValidatorMock = new Mock<IAttestationStatementValidator>();
        attestationStatementValidatorMock
            .Setup(a => a.Validate(It.IsAny<AttestationObjectData>(), It.IsAny<ClientData>()))
            .Returns(ValidatorInternalResult.Valid());

        var attestationTrustworthinessValidatorMock = new Mock<IAttestationTrustworthinessValidator>();
        attestationTrustworthinessValidatorMock
            .Setup(a => a.Validate(It.IsAny<AuthenticatorData>(), It.IsAny<AttestationStatementInternalResult>()))
            .ReturnsAsync(ValidatorInternalResult.Valid());

        var attestationTrustAnchorValidatorMock = new Mock<IAttestationTrustAnchorValidator>();

        _sut = new AttestationObjectValidator(
            attestationStatementValidatorMock.Object,
            attestationTrustworthinessValidatorMock.Object,
            attestationTrustAnchorValidatorMock.Object,
            Options.Create(Fido2ConfigurationBuilder.Build()));
    }

    [Test]
    public async Task Validate_WheniPhoneAttestationObjectDataValid_ThenReturnsValidResult()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);

        // Temporary simplification of tests is to use instance of AuthenticatorDataParserService
        var parserService = new AuthenticatorDataParserService();
        var authenticatorData = parserService.Parse(authenticatorDataArray);

        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatementFormat = AttestationStatementFormatIdentifier.None,
            AuthenticatorData = authenticatorData,
        };

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();
        creationOptions.PublicKeyCredentialParams = [new() { Algorithm = CoseAlgorithm.Es256 }];
        creationOptions.AuthenticatorSelection = new AuthenticatorSelectionCriteria
        {
            UserVerification = UserVerificationRequirement.Required,
        };

        // Act
        var result = await _sut.Validate(attestationObjectData, ClientDataBuilder.BuildCreate(), creationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Validate_WhenWindowsAttestationObjectDataValid_ThenReturnsValidResult()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIHgppX3fEq9YSztHkiwb17ns0+Px0i+cSd9aTkm1JD5LpAEDAzkBACBZAQCmBcYvuGi9gyjh5lXY0wiL0oYw1voBr5XHTwP+14ezQBR90zV93anRBAfqFr5MLzY+0EB+YhwjvhL51G0INgmFS6rUhpfG1wQp+MvSU7tSaK1MwZKB35r17oU77/zjroBt780iDHGdYaUx4UN0Mi4oIGe9pmZTTiSUOwq9KpoE4aixjVQNfurWUs036xnkFJ5ZMVON4ki8dXLuOtqgtNy06/X98EKsFcwNKA83ob6XKUZCnG2GlWQJyMBnE8p1p4k46r3DF5p6vdVH+3Ibujmcxhw/f6/M6UTvhvYofT+ljqFYhHKT2iRp1m2+iFQJAbcGCvXW9AWVWeqU1tBQ5yENIUMBAAE=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);

        // Temporary simplification of tests is to use instance of AuthenticatorDataProvider
        var parserService = new AuthenticatorDataParserService();
        var authenticatorData = parserService.Parse(authenticatorDataArray);

        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatementFormat = AttestationStatementFormatIdentifier.Packed,
            AuthenticatorData = authenticatorData,
        };

        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();
        creationOptions.PublicKeyCredentialParams = [new() { Algorithm = CoseAlgorithm.Rs256 }];
        creationOptions.AuthenticatorSelection = new AuthenticatorSelectionCriteria
        {
            UserVerification = UserVerificationRequirement.Required,
        };

        // Act
        var result = await _sut.Validate(attestationObjectData, ClientDataBuilder.BuildCreate(), creationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}