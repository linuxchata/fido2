using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Extensions;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Handlers;

[TestFixture]
internal class AssertionObjectHandlerTests
{
    private const string AuthenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";

    private IAuthenticatorDataParserService _authenticatorDataParserService = null!;
    private Mock<IAssertionObjectValidator> _assertionObjectValidatorMock = null!;

    private AssertionObjectHandler _sut = null!;

    [SetUp]
    public void Setup()
    {
        _authenticatorDataParserService = new AuthenticatorDataParserService();

        _assertionObjectValidatorMock = new Mock<IAssertionObjectValidator>();
        _assertionObjectValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AuthenticatorData?>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]?>(),
                It.IsAny<string>(),
                It.IsAny<CredentialPublicKey>(),
                It.IsAny<AuthenticationExtensionsClientOutputs>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Returns(ValidatorInternalResult.Valid());

        _sut = new AssertionObjectHandler(
            _authenticatorDataParserService,
            _assertionObjectValidatorMock.Object,
            NullLogger<AssertionObjectHandler>.Instance);
    }

    [Test]
    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void Handle_WhenAuthenticatorDataStringIsNullOrEmpty_ThenReturnsInternalResult(string? authenticatorDataString)
    {
        // Arrange
        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Handle(
            authenticatorDataString!,
            It.IsAny<string>(),
            ClientDataBuilder.BuildCreate(),
            It.IsAny<CredentialPublicKey>(),
            It.IsAny<AuthenticationExtensionsClientOutputs>(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.True);
        Assert.That(result.Message, Is.EqualTo("Attestation Data cannot be null"));
        Assert.That(result.Value, Is.Null);
    }

    [Test]
    public void Handle_WhenRequestOptionsAreNull_ThenReturnsInternalResult()
    {
        // Act
        var result = _sut.Handle(
            AuthenticatorDataString,
            It.IsAny<string>(),
            ClientDataBuilder.BuildCreate(),
            It.IsAny<CredentialPublicKey>(),
            It.IsAny<AuthenticationExtensionsClientOutputs>(),
            null!);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.True);
        Assert.That(result.Message, Is.EqualTo("Request options cannot be null"));
        Assert.That(result.Value, Is.Null);
    }

    [Test]
    public void Handle_WhenAuthenticatorDataStringIsNotValid_ThenReturnsInternalResult()
    {
        // Arrange
        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        _assertionObjectValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AuthenticatorData?>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]?>(),
                It.IsAny<string>(),
                It.IsAny<CredentialPublicKey>(),
                It.IsAny<AuthenticationExtensionsClientOutputs>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Returns(ValidatorInternalResult.Invalid("RP ID hash mismatch"));

        // Act
        var result = _sut.Handle(
            AuthenticatorDataString,
            It.IsAny<string>(),
            ClientDataBuilder.BuildCreate(),
            It.IsAny<CredentialPublicKey>(),
            It.IsAny<AuthenticationExtensionsClientOutputs>(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.True);
        Assert.That(result.Message, Is.EqualTo("RP ID hash mismatch"));
        Assert.That(result.Value, Is.Null);
    }

    [Test]
    public void Handle_WhenAuthenticatorDataStringIsValid_ThenReturnsValue()
    {
        // Arrange
        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Handle(
            AuthenticatorDataString,
            It.IsAny<string>(),
            ClientDataBuilder.BuildCreate(),
            It.IsAny<CredentialPublicKey>(),
            It.IsAny<AuthenticationExtensionsClientOutputs>(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);
    }
}
