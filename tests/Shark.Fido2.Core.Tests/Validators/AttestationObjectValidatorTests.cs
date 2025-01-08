using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
public class AttestationObjectValidatorTests
{
    private AttestationObjectValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        var fido2ConfigurationMock = new Fido2Configuration
        {
            Origin = "localhost",
            RelyingPartyId = "localhost",
        };

        _sut = new AttestationObjectValidator(Options.Create(fido2ConfigurationMock));
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

        // Act
        var result = _sut.Validate(attestationObjectData);

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

        // Temporary simplification of tests is to use instance of AuthenticatorDataProvider
        var provider = new AuthenticatorDataProvider();
        var authenticatorData = provider.Get(authenticatorDataArray);

        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatementFormat = AttestationStatementFormatIdentifier.None,
            AuthenticatorData = authenticatorData,
        };

        // Act
        var result = _sut.Validate(attestationObjectData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }
}