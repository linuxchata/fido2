using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests;

[TestFixture]
public class AttestationTests
{
    private const string UserName = "testuser";
    private const string DisplayName = "Test User";
    private const string AttestationId = "AttestationId";
    private const string AttestationRawId = "AttestationRawId";

    private Mock<IClientDataHandler> _clientDataHandlerMock = null!;
    private Mock<IAttestationObjectHandler> _attestationObjectHandlerMock = null!;
    private Mock<IChallengeGenerator> _challengeGeneratorMock = null!;
    private Mock<ICredentialRepository> _credentialRepositoryMock = null!;
    private Fido2Configuration _fido2Configuration = null!;
    private PublicKeyCredentialCreationOptions _publicKeyCredentialCreationOptions = null!;
    private PublicKeyCredentialUserEntity _publicKeyCredentialUserEntity = null!;

    private Attestation _sut = null!;

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
            .Returns(new InternalResult<AttestationObjectData>(new AttestationObjectData
            {
                AuthenticatorData = new AuthenticatorData
                {
                    AttestedCredentialData = new AttestedCredentialData
                    {
                        CredentialId = new byte[] { 1, 2, 3, 4 },
                        CredentialPublicKey = new CredentialPublicKey
                        {
                            KeyType = 2, // EC2
                            Algorithm = -7, // ES256
                            Curve = 1, // P-256
                            XCoordinate = new byte[] { 5, 6, 7, 8 },
                            YCoordinate = new byte[] { 9, 10, 11, 12 }
                        }
                    },
                    SignCount = 1
                }
            }));

        _challengeGeneratorMock = new Mock<IChallengeGenerator>();
        _challengeGeneratorMock
            .Setup(a => a.Get())
            .Returns(new byte[] { 1, 2, 3, 4 });

        _credentialRepositoryMock = new Mock<ICredentialRepository>();
        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>()))
            .ReturnsAsync((Credential?)null);

        _fido2Configuration = new Fido2Configuration
        {
            Origin = "localhost",
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Timeout = 60000
        };

        _publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity
        {
            Id = Encoding.UTF8.GetBytes(UserName),
            Name = UserName,
            DisplayName = DisplayName,
        };
        _publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions
        {
            Challenge = [1, 2, 3, 4],
            User = _publicKeyCredentialUserEntity,
        };

        _sut = new Attestation(
            _clientDataHandlerMock.Object,
            _attestationObjectHandlerMock.Object,
            _challengeGeneratorMock.Object,
            _credentialRepositoryMock.Object,
            Options.Create(_fido2Configuration));
    }

    #region GetOptions Tests

    [Test]
    public void GetOptions_WhenRequestIsNull_ThenReturnsOptions()
    {
        // Arrange
        PublicKeyCredentialCreationOptionsRequest? request = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.GetOptions(request!));
    }

    [Test]
    public void GetOptions_WhenAuthenticatorSelectionIsNull_ThenReturnsOptions()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            Username = UserName,
            DisplayName = DisplayName,
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct
        };

        // Act
        var result = _sut.GetOptions(request);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AuthenticatorSelection, Is.Not.Null);
        Assert.That(result.AuthenticatorSelection.AuthenticatorAttachment, Is.EqualTo((AuthenticatorAttachment)0));
        Assert.That(result.AuthenticatorSelection.RequireResidentKey, Is.False);
        Assert.That(result.AuthenticatorSelection.UserVerification, Is.Null);
    }

    [Test]
    public void GetOptions_WhenAttestationIsNull_ThenReturnsOptions()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            Username = UserName,
            DisplayName = DisplayName,
            AuthenticatorSelection = null,
            Attestation = null
        };

        // Act
        var result = _sut.GetOptions(request);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Attestation, Is.EqualTo(AttestationConveyancePreference.None));
    }

    [Test]
    public void GetOptions_WhenRequestIsValid_ThenReturnsOptions()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            Username = UserName,
            DisplayName = DisplayName,
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = AuthenticatorAttachment.Platform,
                ResidentKey = ResidentKeyRequirement.Required,
                RequireResidentKey = true,
                UserVerification = UserVerificationRequirement.Required
            },
            Attestation = AttestationConveyancePreference.Direct
        };

        // Act
        var result = _sut.GetOptions(request);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.RelyingParty.Id, Is.EqualTo(_fido2Configuration.RelyingPartyId));
        Assert.That(result.RelyingParty.Name, Is.EqualTo(_fido2Configuration.RelyingPartyIdName));
        Assert.That(result.User.Name, Is.EqualTo(request.Username));
        Assert.That(result.User.DisplayName, Is.EqualTo(request.DisplayName));
        Assert.That(result.User.Id, Is.EqualTo(Encoding.UTF8.GetBytes(request.Username)));
        Assert.That(result.Challenge, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
        Assert.That(result.PublicKeyCredentialParams.Length, Is.EqualTo(2));
        Assert.That(result.Timeout, Is.EqualTo(60000));
        Assert.That(result.ExcludeCredentials.Length, Is.EqualTo(0));
        Assert.That(result.AuthenticatorSelection.AuthenticatorAttachment, Is.EqualTo(AuthenticatorAttachment.Platform));
        Assert.That(result.AuthenticatorSelection.ResidentKey, Is.EqualTo(ResidentKeyRequirement.Required));
        Assert.That(result.AuthenticatorSelection.RequireResidentKey, Is.True);
        Assert.That(result.AuthenticatorSelection.UserVerification, Is.EqualTo(UserVerificationRequirement.Required));
        Assert.That(result.Attestation, Is.EqualTo(AttestationConveyancePreference.Direct));
    }

    #endregion

    #region Complete Tests

    [Test]
    public void Complete_WhenPublicKeyCredentialAttestationIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        PublicKeyCredentialAttestation? publicKeyCredentialAttestation = null;
        var creationOptions = new PublicKeyCredentialCreationOptions();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() =>
            _sut.Complete(publicKeyCredentialAttestation!, creationOptions));
    }

    [Test]
    public void Complete_WhenPublicKeyCredentialCreationOptionsIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var publicKeyCredentialAttestation = new PublicKeyCredentialAttestation
        {
            Id = AttestationId,
            RawId = AttestationRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationResponse
            {
                ClientDataJson = "test-client-data",
                AttestationObject = "test-attestation-object",
                Transports = [],
            },
        };
        PublicKeyCredentialCreationOptions? creationOptions = null;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() =>
            _sut.Complete(publicKeyCredentialAttestation, creationOptions!));
    }

    [Test]
    public async Task Complete_WhenResponseIsNull_ThenReturnsFailure()
    {
        // Arrange
        var publicKeyCredentialAttestation = new PublicKeyCredentialAttestation
        {
            Id = AttestationId,
            RawId = AttestationRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = null!,
        };
        var publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions();

        // Act
        var result = await _sut.Complete(publicKeyCredentialAttestation, publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("failed"));
        Assert.That(result.Message, Is.EqualTo("Authenticator attestation response cannot be null"));
    }

    [Test]
    public async Task Complete_WhenClientDataHandlerHasError_ThenReturnsFailure()
    {
        // Arrange
        var publicKeyCredentialAttestation = new PublicKeyCredentialAttestation
        {
            Id = AttestationId,
            RawId = AttestationRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationResponse
            {
                ClientDataJson = "invalid-data",
                AttestationObject = "attestation-object",
                Transports = [],
            },
        };

        _clientDataHandlerMock
            .Setup(a => a.Handle(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(new InternalResult<ClientData>("Client data validation failed"));

        // Act
        var result = await _sut.Complete(publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("failed"));
        Assert.That(result.Message, Is.EqualTo("Client data validation failed"));
    }

    [Test]
    public async Task Complete_WhenAttestationObjectHandlerHasError_ThenReturnsFailure()
    {
        // Arrange
        var publicKeyCredentialAttestation = new PublicKeyCredentialAttestation
        {
            Id = AttestationId,
            RawId = AttestationRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationResponse
            {
                ClientDataJson = "client-data",
                AttestationObject = "invalid-attestation",
                Transports = [],
            },
        };

        _attestationObjectHandlerMock
            .Setup(a => a.Handle(
                It.IsAny<string>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>()))
            .Returns(new InternalResult<AttestationObjectData>("Attestation object validation failed"));

        // Act
        var result = await _sut.Complete(publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("failed"));
        Assert.That(result.Message, Is.EqualTo("Attestation object validation failed"));
    }

    [Test]
    public async Task Complete_WhenCredentialAlreadyExists_ThenReturnsFailure()
    {
        // Arrange
        var publicKeyCredential = new PublicKeyCredentialAttestation
        {
            Id = AttestationId,
            RawId = AttestationRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationResponse
            {
                ClientDataJson = "client-data",
                AttestationObject = "attestation-object",
                Transports = [AuthenticatorTransport.Internal],
            },
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>()))
            .ReturnsAsync(new Credential
            {
                CredentialId = [1, 2, 3, 4],
                Username = UserName,
                CredentialPublicKey = new CredentialPublicKey
                {
                    KeyType = 2,
                    Algorithm = -7,
                },
            });

        // Act
        var result = await _sut.Complete(publicKeyCredential, _publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("failed"));
        Assert.That(result.Message, Is.EqualTo("Credential has already been registered"));
    }

    [Test]
    public async Task Complete_WhenPublicKeyCredentialAttestationIsValid_ThenAddsCredentialAndReturnsSuccess()
    {
        // Arrange
        var publicKeyCredentialAttestation = new PublicKeyCredentialAttestation
        {
            Id = AttestationId,
            RawId = AttestationRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationResponse
            {
                ClientDataJson = "client-data",
                AttestationObject = "attestation-object",
                Transports = [AuthenticatorTransport.Internal, AuthenticatorTransport.Usb],
            }
        };

        Credential? addedCredential = null;
        _credentialRepositoryMock
            .Setup(a => a.Add(It.IsAny<Credential>()))
            .Callback<Credential>(c => addedCredential = c)
            .Returns(Task.CompletedTask);

        // Act
        var result = await _sut.Complete(publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("ok"));
        Assert.That(result.Message, Is.Null);

        _credentialRepositoryMock.Verify(a => a.Add(It.IsAny<Credential>()), Times.Once);
        Assert.That(addedCredential, Is.Not.Null);
        Assert.That(addedCredential!.CredentialId, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
        Assert.That(addedCredential.CredentialPublicKey.KeyType, Is.EqualTo(2));
        Assert.That(addedCredential.CredentialPublicKey.Algorithm, Is.EqualTo(-7));
        Assert.That(addedCredential.CredentialPublicKey.Curve, Is.EqualTo(1));
        Assert.That(addedCredential.CredentialPublicKey.XCoordinate, Is.EqualTo(new byte[] { 5, 6, 7, 8 }));
        Assert.That(addedCredential.CredentialPublicKey.YCoordinate, Is.EqualTo(new byte[] { 9, 10, 11, 12 }));
        Assert.That(addedCredential.SignCount, Is.EqualTo(1));
        Assert.That(addedCredential.Transports, Is.EquivalentTo(new[] { "internal", "usb" }));
    }

    [Test]
    public async Task Complete_WheniPhoneAndPublicKeyCredentialAttestationIsValid_ThenReturnsSuccess()
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
                Transports = [],
            },
            Type = PublicKeyCredentialType.PublicKey,
        };

        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";
        var publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions
        {
            Challenge = Convert.FromBase64String($"{expectedChallenge}=="),
            User = _publicKeyCredentialUserEntity,
        };

        // Act
        var result = await _sut.Complete(publicKeyCredential, publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("ok"));
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task Complete_WhenWindowsAndPublicKeyCredentialAttestationIsValid_ThenReturnsSuccess()
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
                Transports = [],
            },
            Type = PublicKeyCredentialType.PublicKey,
        };

        var expectedChallenge = "gsjJTjg3rcml3cfELwxAxQ";
        var publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions
        {
            Challenge = Convert.FromBase64String($"{expectedChallenge}=="),
            User = _publicKeyCredentialUserEntity,
        };

        // Act
        var result = await _sut.Complete(publicKeyCredential, publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo("ok"));
        Assert.That(result.Message, Is.Null);
    }

    #endregion
}
