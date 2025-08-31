using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class AssertionResponseValidatorTests
{
    private AuthenticatorData _authenticatorData;

    private Mock<ISignatureAttestationStatementValidator> _signatureAttestationStatementValidatorMock;

    private AssertionResponseValidator _sut;

    [SetUp]
    public void Setup()
    {
        _authenticatorData = new AuthenticatorData
        {
            AttestedCredentialData = new AttestedCredentialData(),
            UserPresent = true,
            UserVerified = true,
        };

        _signatureAttestationStatementValidatorMock = new Mock<ISignatureAttestationStatementValidator>();
        _signatureAttestationStatementValidatorMock
            .Setup(a => a.Validate(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<CredentialPublicKey>()))
            .Returns(ValidatorInternalResult.Valid());

        _sut = new AssertionResponseValidator(
            _signatureAttestationStatementValidatorMock.Object,
            Options.Create(Fido2ConfigurationBuilder.Build()));
    }

    [Test]
    public void Validate_WhenAuthenticatorDataIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        AuthenticatorData? authenticatorData = null;

        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Validate(
            authenticatorData!,
            [],
            [],
            "signature",
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Authenticator data cannot be null"));
    }

    [Test]
    public void Validate_WhenSignatureIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Validate(
            _authenticatorData,
            [],
            [],
            null!,
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Signature cannot be null"));
    }

    [Test]
    public void Validate_WhenExtensionsClientOutputsIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Validate(
            _authenticatorData,
            [],
            [],
            "signature",
            new CredentialPublicKey(),
            null!,
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Extensions client outputs cannot be null"));
    }

    [Test]
    public void Validate_WhenRequestOptionsIsNull_ThenReturnsInvalidResult()
    {
        // Act
        var result = _sut.Validate(
            _authenticatorData,
            [],
            [],
            "signature",
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            null!);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Request options cannot be null"));
    }
}
