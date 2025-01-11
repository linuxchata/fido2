using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
public class AttestationObjectValidatorTests
{
    private AttestationObjectValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        var attestationStatementValidatorMock = new Mock<IAttestationStatementValidator>();

        var fido2ConfigurationMock = new Fido2Configuration
        {
            Origin = "localhost",
            RelyingPartyId = "localhost",
        };

        _sut = new AttestationObjectValidator(
            attestationStatementValidatorMock.Object,
            Options.Create(fido2ConfigurationMock));
    }

    [Test]
    public void Validate_WheniPhoneClientDataValid_ThenReturnsValidResult()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);

        // Temporary simplification of tests is to use instance of AuthenticatorDataProvider
        var provider = new AuthenticatorDataProvider();
        var authenticatorData = provider.Get(authenticatorDataArray);

        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatementFormat = AttestationStatementFormatIdentifier.None,
            AuthenticatorData = authenticatorData,
        };

        var creationOptions = new PublicKeyCredentialCreationOptions
        {
            PublicKeyCredentialParams = [ new() { Algorithm = PublicKeyAlgorithm.Es256 } ],
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                UserVerification = UserVerificationRequirement.Required,
            },
        };

        // Act
        var result = _sut.Validate(attestationObjectData, creationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenWindowsClientDataValid_ThenReturnsValidResult()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIPbZ8TFtu1QIdgyeU/8pErsPUlpyNOO78e5M2fuf6qbapAEDAzkBACBZAQDyo0pfoOrWf6nTz8BLydkpXJwNwU4cdciPBhSrj3oUif0N4MoXDE4cwoBgbtGQ4MVVwKbnn+iTsmi/TJc+G9tIX/LPRyj+0Z2bcMW1TJr1vD3BurP5VV4pd7eeQofWbO0zG7pSn6P/txKRqkCtQu0drUXlfrOek/P1v7rruhAvcXq4JNdVEeajP6OARISK/G62CcpI122cZ/CYH41/4ES0Ik0HgmwtEkRZrQQXAksDWVtf6Cq0xv6nL9CB+b8Stx2jEei5P9mHhP0Kanj0eEUXmjB1kVmwxMSWM0iSc8E9lefS0os9Cue/32eqzf0ybOVaObVb+BUE1kjzrRwmIOjZIUMBAAE=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);

        var signatureString = "jFsg1pE0oG+yOUWvf7E/E5aP8DuA9q1fnxk2GZfRn8vQNhqz5Wkx/Zqyevp8RDh+EwjYJIkK3nrLYvTzbnGKMhFSdOJ2N2hacvSO3SsQ890DYTONlVThN6/PpPn4DZ+fEa/yr68vWXm5Lma2GDuJ4gSL08RFPWoerzQtWMNCE4aIv988JJvmIU6BA/uzux3kX9E2Golpn8Vs4XW53U0EsED6TyImTOuCtbSfB8/xkcq2JuhRaJwHQqaV2tIKHnqtvGFDB7yPMxiGi/Skzyv2QitsdlY4DS4jXDH4HrA1VxzIRjBbjfofy0WRAxJtgrEK7a0ZEOEPhaW0vqPR5KZHvQ==";
        var signatureArray = Convert.FromBase64String(signatureString);

        // Temporary simplification of tests is to use instance of AuthenticatorDataProvider
        var provider = new AuthenticatorDataProvider();
        var authenticatorData = provider.Get(authenticatorDataArray);

        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatementFormat = AttestationStatementFormatIdentifier.Packed,
            AttestationStatement = new Dictionary<string, object>
            {
                { "alg", PublicKeyAlgorithm.Rs256 },
                { "sig", signatureArray },
            },
            AuthenticatorData = authenticatorData,
        };

        var creationOptions = new PublicKeyCredentialCreationOptions
        {
            PublicKeyCredentialParams = [new() { Algorithm = PublicKeyAlgorithm.Rs256 }],
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                UserVerification = UserVerificationRequirement.Required,
            },
        };

        // Act
        var result = _sut.Validate(attestationObjectData, creationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}