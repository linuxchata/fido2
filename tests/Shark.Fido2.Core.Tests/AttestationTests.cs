using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;

namespace Shark.Fido2.Core.Tests;

[TestFixture]
public class AttestationTests
{
    private Attestation _sut = null!;
    private Mock<IClientDataHandler> _clientDataHandlerMock = null!;
    private Mock<IAttestationObjectHandler> _attestationObjectHandlerMock = null!;
    private Mock<ICredentialRepository> _credentialRepositoryMock = null!;

    [SetUp]
    public void Setup()
    {
        _clientDataHandlerMock = new Mock<IClientDataHandler>();
        _clientDataHandlerMock
            .Setup(a => a.Handle(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(new InternalResult<ClientData>(new ClientData()));

        _attestationObjectHandlerMock = new Mock<IAttestationObjectHandler>();
        _attestationObjectHandlerMock
            .Setup(a => a.Handle(
                It.IsAny<string>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>()))
            .Returns(new InternalResult<AttestationObjectData>(new AttestationObjectData { AuthenticatorData = new AuthenticatorData() }));

        var challengeGeneratorMock = new Mock<IChallengeGenerator>();

        _credentialRepositoryMock = new Mock<ICredentialRepository>();
        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>()))
            .ReturnsAsync((Credential?)null);

        var fido2ConfigurationMock = new Fido2Configuration
        {
            Origin = "localhost",
        };

        _sut = new Attestation(
            _clientDataHandlerMock.Object,
            _attestationObjectHandlerMock.Object,
            challengeGeneratorMock.Object,
            _credentialRepositoryMock.Object,
            Options.Create(fido2ConfigurationMock));
    }

    [Test]
    public async Task Complete_WheniPhoneAndPublicKeyCredentialValid_ThenReturnsSuccess()
    {
        // Arrange
        var publicKeyCredential = new PublicKeyCredentialAttestation
        {
            Id = "0g4ho5WAlHIjp98Ty01Xi0e8YlU",
            RawId = "0g4ho5WAlHIjp98Ty01Xi0e8YlU=",
            Response = new AuthenticatorAttestationResponse
            {
                AttestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=",
                ClientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidDJwSkdJUTdZNERYRjJiOTh0bkJqZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==",
                Signature = string.Empty,
                UserHandler = string.Empty,
            },
            Type = PublicKeyCredentialType.PublicKey,
        };

        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";
        var publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions
        {
            Challenge = Convert.FromBase64String($"{expectedChallenge}=="),
        };

        // Act
        var result = await _sut.Complete(publicKeyCredential, publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo(ResponseStatus.Ok));
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Complete_WhenWindowsAndPublicKeyCredentialValid_ThenReturnsSuccess()
    {
        // Arrange
        var publicKeyCredential = new PublicKeyCredentialAttestation
        {
            Id = "eCmlfd8Sr1hLO0eSLBvXuezT4_HSL5xJ31pOSbUkPks",
            RawId = "eCmlfd8Sr1hLO0eSLBvXuezT4/HSL5xJ31pOSbUkPks=",
            Response = new AuthenticatorAttestationResponse
            {
                AttestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQClP2a8p8lm+FUiGJAUj76ThUfAVUUWut6EVWUdZvC4/HBxyOCh3sZ15o+CgW4TA1dPYZpYJAx1f7AdK5JXJ7MEpgmIuVWTNklGSyWBI5FJWDgGg0LDzDFZqDuGFbupXPzWT9PP4/yBTOcAQ2ZM6YMe7o7ix95Ke9PZnyQ30oySbVyUINCQZTZucBJh9cGfb92na5I2iNEfd7JN80ea3g58xBjEol+jLAmkfPabTVa4PDuI3B7PtjV2AbpmFjB3yfq+PpScSTObjx9EqZ3EsSvEZHAfj9LwhMbEkBzDEfUxHt6xW9Vgqn32aV7VAKdkohTh5CUZNGFIC2CvKjeqFBWWaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIHgppX3fEq9YSztHkiwb17ns0+Px0i+cSd9aTkm1JD5LpAEDAzkBACBZAQCmBcYvuGi9gyjh5lXY0wiL0oYw1voBr5XHTwP+14ezQBR90zV93anRBAfqFr5MLzY+0EB+YhwjvhL51G0INgmFS6rUhpfG1wQp+MvSU7tSaK1MwZKB35r17oU77/zjroBt780iDHGdYaUx4UN0Mi4oIGe9pmZTTiSUOwq9KpoE4aixjVQNfurWUs036xnkFJ5ZMVON4ki8dXLuOtqgtNy06/X98EKsFcwNKA83ob6XKUZCnG2GlWQJyMBnE8p1p4k46r3DF5p6vdVH+3Ibujmcxhw/f6/M6UTvhvYofT+ljqFYhHKT2iRp1m2+iFQJAbcGCvXW9AWVWeqU1tBQ5yENIUMBAAE=",
                ClientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZ3NqSlRqZzNyY21sM2NmRUx3eEF4USIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                Signature = string.Empty,
                UserHandler = string.Empty,
            },
            Type = PublicKeyCredentialType.PublicKey,
        };

        var expectedChallenge = "gsjJTjg3rcml3cfELwxAxQ";
        var publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions
        {
            Challenge = Convert.FromBase64String($"{expectedChallenge}=="),
        };

        // Act
        var result = await _sut.Complete(publicKeyCredential, publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo(ResponseStatus.Ok));
        Assert.That(result.Message, Is.Null);
    }
}