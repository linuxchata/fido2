using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Validators;

namespace Shark.Fido2.Core.Tests.Validators;

public class AttestationObjectValidatorTests
{
    private AttestationObjectValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new AttestationObjectValidator();
    }

    [Test]
    public void Validate_WhenClientDataValid_ThenReturnsNull()
    {
        // Arrange
        // Temporary simplification of tests is to use instance of AuthenticatorDataProvider
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);
        var provider = new AuthenticatorDataProvider();
        var authenticatorData = provider.Get(authenticatorDataArray);

        // Act
        var result = _sut.Validate(authenticatorData);

        // Assert
        Assert.That(result, Is.Null);
    }
}