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
        Assert.That(result.AttestedCredentialData, Is.Not.Null);
        Assert.That(result.AttestedCredentialData.CredentialPublicKey, Is.Not.Null);
    }
}