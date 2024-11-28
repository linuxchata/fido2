using Moq;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Core.Results;

namespace Shark.Fido2.Core.Tests.Handlers;

public class AttestationObjectHandlerTests
{
    private AttestationObjectHandler _sut = null!;
    private IAuthenticatorDataProvider _authenticatorDataProvider = null!;
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;

    [SetUp]
    public void Setup()
    {
        _authenticatorDataProvider = new AuthenticatorDataProvider();
        _attestationObjectValidatorMock = new Mock<IAttestationObjectValidator>();

        _sut = new AttestationObjectHandler(
            _authenticatorDataProvider,
            _attestationObjectValidatorMock.Object);
    }

    [Test]
    public void Handle_WhenAttestationObjectValid_ThenReturnsNull()
    {
        // Arrange
        var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";

        _attestationObjectValidatorMock
            .Setup(a => a.Validate(It.IsAny<AttestationObjectDataModel?>()))
            .Returns(ValidatorInternalResult.Valid());

        // Act
        var result = _sut.Handle(attestationObject);

        // Assert
        Assert.That(result, Is.Not.Null);
    }
}