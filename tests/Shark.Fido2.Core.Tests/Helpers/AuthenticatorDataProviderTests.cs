using Shark.Fido2.Core.Helpers;

namespace Shark.Fido2.Core.Tests.Helpers;

internal class AuthenticatorDataProviderTests
{
    private AuthenticatorDataProvider _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new AuthenticatorDataProvider();
    }

    [Test]
    public void Get_WheniPhoneAuthenticatorDataValid_ThenDoesNotReturnNull()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";
        var authenticatorData = Convert.FromBase64String(authenticatorDataString);

        // Act
        var result = _sut.Get(authenticatorData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.AttestedCredentialData, Is.Not.Null);
        Assert.That(result.AttestedCredentialData.CredentialPublicKey, Is.Not.Null);
    }

    [Test]
    public void Get_WhenWindowsAuthenticatorDataValid_ThenDoesNotReturnNull()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIPbZ8TFtu1QIdgyeU/8pErsPUlpyNOO78e5M2fuf6qbapAEDAzkBACBZAQDyo0pfoOrWf6nTz8BLydkpXJwNwU4cdciPBhSrj3oUif0N4MoXDE4cwoBgbtGQ4MVVwKbnn+iTsmi/TJc+G9tIX/LPRyj+0Z2bcMW1TJr1vD3BurP5VV4pd7eeQofWbO0zG7pSn6P/txKRqkCtQu0drUXlfrOek/P1v7rruhAvcXq4JNdVEeajP6OARISK/G62CcpI122cZ/CYH41/4ES0Ik0HgmwtEkRZrQQXAksDWVtf6Cq0xv6nL9CB+b8Stx2jEei5P9mHhP0Kanj0eEUXmjB1kVmwxMSWM0iSc8E9lefS0os9Cue/32eqzf0ybOVaObVb+BUE1kjzrRwmIOjZIUMBAAE=";
        var authenticatorData = Convert.FromBase64String(authenticatorDataString);

        // Act
        var result = _sut.Get(authenticatorData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.AttestedCredentialData, Is.Not.Null);
        Assert.That(result.AttestedCredentialData.CredentialPublicKey, Is.Not.Null);
    }
}