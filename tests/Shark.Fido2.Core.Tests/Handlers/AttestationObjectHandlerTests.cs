using Moq;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

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
    public void Handle_WheniPhoneAttestationObjectValid_ThenReturnsNull()
    {
        // Arrange
        var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";

        _attestationObjectValidatorMock
            .Setup(a => a.Validate(It.IsAny<AttestationObjectData?>()))
            .Returns(ValidatorInternalResult.Valid());

        // Act
        var result = _sut.Handle(attestationObject);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void Handle_WhenWindowsAttestationObjectValid_ThenReturnsNull()
    {
        // Arrange
        var attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQCMWyDWkTSgb7I5Ra9/sT8Tlo/wO4D2rV+fGTYZl9Gfy9A2GrPlaTH9mrJ6+nxEOH4TCNgkiQreesti9PNucYoyEVJ04nY3aFpy9I7dKxDz3QNhM42VVOE3r8+k+fgNn58Rr/Kvry9ZebkuZrYYO4niBIvTxEU9ah6vNC1Yw0IThoi/3zwkm+YhToED+7O7HeRf0TYaiWmfxWzhdbndTQSwQPpPIiZM64K1tJ8Hz/GRyrYm6FFonAdCppXa0goeeq28YUMHvI8zGIaL9KTPK/ZCK2x2VjgNLiNcMfgesDVXHMhGMFuN+h/LRZEDEm2CsQrtrRkQ4Q+FpbS+o9Hkpke9aGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIPbZ8TFtu1QIdgyeU/8pErsPUlpyNOO78e5M2fuf6qbapAEDAzkBACBZAQDyo0pfoOrWf6nTz8BLydkpXJwNwU4cdciPBhSrj3oUif0N4MoXDE4cwoBgbtGQ4MVVwKbnn+iTsmi/TJc+G9tIX/LPRyj+0Z2bcMW1TJr1vD3BurP5VV4pd7eeQofWbO0zG7pSn6P/txKRqkCtQu0drUXlfrOek/P1v7rruhAvcXq4JNdVEeajP6OARISK/G62CcpI122cZ/CYH41/4ES0Ik0HgmwtEkRZrQQXAksDWVtf6Cq0xv6nL9CB+b8Stx2jEei5P9mHhP0Kanj0eEUXmjB1kVmwxMSWM0iSc8E9lefS0os9Cue/32eqzf0ybOVaObVb+BUE1kjzrRwmIOjZIUMBAAE=";

        _attestationObjectValidatorMock
            .Setup(a => a.Validate(It.IsAny<AttestationObjectData?>()))
            .Returns(ValidatorInternalResult.Valid());

        // Act
        var result = _sut.Handle(attestationObject);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);
    }
}