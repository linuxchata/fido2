using Moq;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.Handlers;

[TestFixture]
public class AttestationObjectHandlerTests
{
    private AttestationObjectHandler _sut = null!;
    private IAuthenticatorDataParserService _authenticatorDataParserService = null!;
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;

    [SetUp]
    public void Setup()
    {
        _authenticatorDataParserService = new AuthenticatorDataParserService();

        _attestationObjectValidatorMock = new Mock<IAttestationObjectValidator>();
        _attestationObjectValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AttestationObjectData?>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>()))
            .Returns(ValidatorInternalResult.Valid());

        _sut = new AttestationObjectHandler(
            _authenticatorDataParserService,
            _attestationObjectValidatorMock.Object);
    }

    [Test]
    public void Handle_WheniPhone8AttestationObjectValid_ThenReturnsNull()
    {
        // Arrange
        var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";
        var creationOptions = new PublicKeyCredentialCreationOptions();

        // Act
        var result = _sut.Handle(attestationObject, new ClientData(), creationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void Handle_WheniPhone14AttestationObjectValid_ThenReturnsNull()
    {
        // Arrange
        var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMM5L/63IyA9jqYyiZ9EaOwWhG40pQECAyYgASFYIHFhbupdvz+UhnJF4mph/jreh1RzjE7NDyl54kPLlbiLIlggdqxWZTTqfjbFSXBmGW0RWEJfvljHTKfB9upz0SBkPj8=";
        var creationOptions = new PublicKeyCredentialCreationOptions();

        // Act
        var result = _sut.Handle(attestationObject, new ClientData(), creationOptions);

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
        var attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQClP2a8p8lm+FUiGJAUj76ThUfAVUUWut6EVWUdZvC4/HBxyOCh3sZ15o+CgW4TA1dPYZpYJAx1f7AdK5JXJ7MEpgmIuVWTNklGSyWBI5FJWDgGg0LDzDFZqDuGFbupXPzWT9PP4/yBTOcAQ2ZM6YMe7o7ix95Ke9PZnyQ30oySbVyUINCQZTZucBJh9cGfb92na5I2iNEfd7JN80ea3g58xBjEol+jLAmkfPabTVa4PDuI3B7PtjV2AbpmFjB3yfq+PpScSTObjx9EqZ3EsSvEZHAfj9LwhMbEkBzDEfUxHt6xW9Vgqn32aV7VAKdkohTh5CUZNGFIC2CvKjeqFBWWaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIHgppX3fEq9YSztHkiwb17ns0+Px0i+cSd9aTkm1JD5LpAEDAzkBACBZAQCmBcYvuGi9gyjh5lXY0wiL0oYw1voBr5XHTwP+14ezQBR90zV93anRBAfqFr5MLzY+0EB+YhwjvhL51G0INgmFS6rUhpfG1wQp+MvSU7tSaK1MwZKB35r17oU77/zjroBt780iDHGdYaUx4UN0Mi4oIGe9pmZTTiSUOwq9KpoE4aixjVQNfurWUs036xnkFJ5ZMVON4ki8dXLuOtqgtNy06/X98EKsFcwNKA83ob6XKUZCnG2GlWQJyMBnE8p1p4k46r3DF5p6vdVH+3Ibujmcxhw/f6/M6UTvhvYofT+ljqFYhHKT2iRp1m2+iFQJAbcGCvXW9AWVWeqU1tBQ5yENIUMBAAE=";
        var creationOptions = new PublicKeyCredentialCreationOptions();

        // Act
        var result = _sut.Handle(attestationObject, new ClientData(), creationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);
    }
}