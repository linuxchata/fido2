using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class AssertionResponseValidatorTests
{
    private const string Signature = "signature";

    private AuthenticatorData _authenticatorData;

    private Mock<ISignatureAttestationStatementValidator> _signatureAttestationStatementValidatorMock;

    private AssertionResponseValidator _sut;

    [SetUp]
    public void Setup()
    {
        _authenticatorData = new AuthenticatorData
        {
            RpIdHash = Convert.FromBase64String("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2M="),
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
            Signature,
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
            Signature,
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
            Signature,
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            null!);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Request options cannot be null"));
    }

    [Test]
    public void Validate_WhenRpIdHashMismatched_ThenReturnsInvalidResult()
    {
        // Arrange
        var authenticatorData = new AuthenticatorData
        {
            RpIdHash = [0x00, 0x01],
            AttestedCredentialData = new AttestedCredentialData(),
            UserPresent = true,
            UserVerified = true,
        };

        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Validate(
            authenticatorData,
            [],
            [],
            Signature,
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("RP ID hash mismatch"));
    }

    [Test]
    public void Validate_WhenUserIsNotPresent_ThenReturnsInvalidResult()
    {
        // Arrange
        var authenticatorData = new AuthenticatorData
        {
            RpIdHash = _authenticatorData.RpIdHash,
            AttestedCredentialData = new AttestedCredentialData(),
            UserPresent = false,
            UserVerified = false,
        };

        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Validate(
            authenticatorData,
            [],
            [],
            Signature,
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User Present bit is not set"));
    }

    [Test]
    public void Validate_WhenUserVerificationRequiredAndUserIsNotVerified_ThenReturnsInvalidResult()
    {
        // Arrange
        var authenticatorData = new AuthenticatorData
        {
            RpIdHash = _authenticatorData.RpIdHash,
            AttestedCredentialData = new AttestedCredentialData(),
            UserPresent = true,
            UserVerified = false,
        };

        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Validate(
            authenticatorData,
            [],
            [],
            Signature,
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User Verified bit is not set as user verification is required"));
    }

    [Test]
    public void Validate_WhenSignatureValidationFails_ThenReturnsInvalidResult()
    {
        // Arrange
        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        _signatureAttestationStatementValidatorMock
            .Setup(a => a.Validate(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<CredentialPublicKey>()))
            .Returns(ValidatorInternalResult.Invalid("Attestation statement signature is not valid"));

        // Act
        var result = _sut.Validate(
            _authenticatorData,
            [],
            [],
            Signature,
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation statement signature is not valid"));
    }

    [Test]
    public void Validate_WhenAuthenticatorDataIsValid_ThenReturnsValidResult()
    {
        // Arrange
        var requestOptions = PublicKeyCredentialRequestOptionsBuilder.Build();

        // Act
        var result = _sut.Validate(
            _authenticatorData,
            [],
            [],
            Signature,
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenAuthenticatorDataIsValidAndRpIdIsInExtension_ThenReturnsValidResult()
    {
        // Arrange
        var extensionsClientOutputs = new AuthenticationExtensionsClientOutputs
        {
            AppId = true,
        };

        var requestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = new byte[32],
            UserVerification = UserVerificationRequirement.Required,
            Extensions = new AuthenticationExtensionsClientInputs
            {
                AppId = "localhost",
            },
        };

        // Act
        var result = _sut.Validate(
            _authenticatorData,
            [],
            [],
            Signature,
            new CredentialPublicKey(),
            extensionsClientOutputs,
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    [TestCase(null)]
    [TestCase(false)]
    public void Validate_WhenAuthenticatorDataIsValidAndRpIdIsInRequestOptions_ThenReturnsValidResult(bool? appId)
    {
        // Arrange
        var extensionsClientOutputs = new AuthenticationExtensionsClientOutputs
        {
            AppId = appId,
        };

        var requestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = new byte[32],
            UserVerification = UserVerificationRequirement.Required,
            RpId = "localhost",
        };

        // Act
        var result = _sut.Validate(
            _authenticatorData,
            [],
            [],
            Signature,
            new CredentialPublicKey(),
            extensionsClientOutputs,
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    [TestCase(UserVerificationRequirement.Preferred)]
    [TestCase(UserVerificationRequirement.Discouraged)]
    public void Validate_WhenAuthenticatorDataIsValidAndUserVerificationIsNotRequired_ThenReturnsValidResult(
        UserVerificationRequirement userVerification)
    {
        // Arrange
        var authenticatorData = new AuthenticatorData
        {
            RpIdHash = _authenticatorData.RpIdHash,
            AttestedCredentialData = new AttestedCredentialData(),
            UserPresent = true,
            UserVerified = false,
        };

        var requestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = new byte[32],
            UserVerification = userVerification,
        };

        // Act
        var result = _sut.Validate(
            authenticatorData,
            [],
            [],
            Signature,
            new CredentialPublicKey(),
            new AuthenticationExtensionsClientOutputs(),
            requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}
