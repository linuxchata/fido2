using Moq;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;

namespace Shark.Fido2.Core.Tests.Handlers;

public class AttestationObjectHandlerTests
{
    private AttestationObjectHandler _sut = null!;
    private Mock<IAuthenticatorDataProvider> _authenticatorDataProviderMock = null!;
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;

    [SetUp]
    public void Setup()
    {
        _authenticatorDataProviderMock = new Mock<IAuthenticatorDataProvider>();
        _attestationObjectValidatorMock = new Mock<IAttestationObjectValidator>();

        _sut = new AttestationObjectHandler(
            _authenticatorDataProviderMock.Object,
            _attestationObjectValidatorMock.Object);
    }

    [Test]
    public void Handle_WhenClientDataJsonValid_ThenReturnsNull()
    {
        // Arrange
        var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";

        // Act
        var result = _sut.Handle(attestationObject);

        // Assert
        Assert.That(result, Is.Null);
    }
}