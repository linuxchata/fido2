﻿using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
public class AssertionParametersValidatorTests
{
    private const string CredentialIdBase64 = "AQIDBA=="; // Base64 for [1,2,3,4]
    private const string CredentialRawId = "AQIDBA==";

    private PublicKeyCredentialAssertion _publicKeyCredentialAssertion = null!;
    private PublicKeyCredentialRequestOptions _publicKeyCredentialRequestOptions = null!;

    private AssertionParametersValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _publicKeyCredentialAssertion = new PublicKeyCredentialAssertion
        {
            Id = CredentialIdBase64,
            RawId = CredentialRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAssertionResponse
            {
                ClientDataJson = "test-client-data",
                AuthenticatorData = "test-authenticator-data",
                Signature = "test-signature",
            },
            Extensions = new AuthenticationExtensionsClientOutputs(),
        };

        _publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = [1, 2, 3, 4],
            RpId = "localhost",
            Timeout = 60000,
            UserVerification = UserVerificationRequirement.Preferred,
        };

        _sut = new AssertionParametersValidator();
    }

    [Test]
    public void Validate_WhenRequestIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        PublicKeyCredentialRequestOptionsRequest? request = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(request!));
    }

    [Test]
    public void Validate_WhenUserNameIsLongerThanAllowedLength_ThenThrowsArgumentException()
    {
        // Arrange
        var request = new PublicKeyCredentialRequestOptionsRequest
        {
            UserName = new string('*', 65),
            UserVerification = UserVerificationRequirement.Preferred,
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(request));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialAssertionIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        PublicKeyCredentialAssertion? publicKeyCredentialAssertion = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(
            () => _sut.Validate(publicKeyCredentialAssertion!, _publicKeyCredentialRequestOptions));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialRequestOptionsIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        PublicKeyCredentialRequestOptions? requestOptions = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAssertion, requestOptions!));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialAttestationIdIsInvalid_ThenReturnsFailure()
    {
        // Arrange
        _publicKeyCredentialAssertion.Id = "aaa";

        // Act
        var result = _sut.Validate(_publicKeyCredentialAssertion, _publicKeyCredentialRequestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Assertion identifier is not Base64URL-encoded"));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialAssertionTypeIsInvalid_ThenReturnsFailure()
    {
        // Arrange
        _publicKeyCredentialAssertion.Type = "invalid-type";

        // Act
        var result = _sut.Validate(_publicKeyCredentialAssertion, _publicKeyCredentialRequestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Assertion type is not set to \"public-key\""));
    }
}
