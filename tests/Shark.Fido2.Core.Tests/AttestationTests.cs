using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Extensions;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests;

[TestFixture]
internal class AttestationTests
{
    private const string UserName = "UserName";
    private const string DisplayName = "DisplayName";
    private const string CredentialId = "AQIDBA=="; // Base64 for [1,2,3,4]
    private const string CredentialRawId = "AQIDBA==";

    private Mock<IAttestationParametersValidator> _attestationParametersValidatorMock = null!;
    private Mock<IClientDataHandler> _clientDataHandlerMock = null!;
    private Mock<IAttestationObjectHandler> _attestationObjectHandlerMock = null!;
    private Mock<IChallengeGenerator> _challengeGeneratorMock = null!;
    private Mock<IUserIdGenerator> _userIdGeneratorMock = null!;
    private Mock<ICredentialRepository> _credentialRepositoryMock = null!;

    private PublicKeyCredentialAttestation _attestation = null!;
    private PublicKeyCredentialCreationOptions _creationOptions = null!;
    private PublicKeyCredentialUserEntity _userEntity = null!;
    private Fido2Configuration _fido2Configuration = null!;

    private Attestation _sut = null!;

    [SetUp]
    public void Setup()
    {
        _attestationParametersValidatorMock = new Mock<IAttestationParametersValidator>();
        _attestationParametersValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<PublicKeyCredentialAttestation>(),
                It.IsAny<PublicKeyCredentialCreationOptions>()))
            .Returns(AttestationCompleteResult.Create());

        _clientDataHandlerMock = new Mock<IClientDataHandler>();
        _clientDataHandlerMock
            .Setup(a => a.HandleAttestation(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(new InternalResult<ClientData>(ClientDataBuilder.BuildCreate()));

        _attestationObjectHandlerMock = new Mock<IAttestationObjectHandler>();
        _attestationObjectHandlerMock
            .Setup(a => a.Handle(
                It.IsAny<string>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InternalResult<AttestationObjectData>(new AttestationObjectData
            {
                AuthenticatorData = new AuthenticatorData
                {
                    AttestedCredentialData = new AttestedCredentialData
                    {
                        CredentialId = [1, 2, 3, 4],
                        CredentialPublicKey = new CredentialPublicKey
                        {
                            KeyType = 2, // EC2
                            Algorithm = -7, // ES256
                            Curve = 1, // P-256
                            XCoordinate = [5, 6, 7, 8],
                            YCoordinate = [9, 10, 11, 12],
                        },
                    },
                    SignCount = 1,
                },
            }));

        _challengeGeneratorMock = new Mock<IChallengeGenerator>();
        _challengeGeneratorMock
            .Setup(a => a.Get())
            .Returns([1, 2, 3, 4]);

        _userIdGeneratorMock = new Mock<IUserIdGenerator>();
        _userIdGeneratorMock
            .Setup(a => a.Get(UserName))
            .Returns([82, 199, 171, 53, 169, 158]);

        _credentialRepositoryMock = new Mock<ICredentialRepository>();
        _credentialRepositoryMock
            .Setup(a => a.Exists(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _fido2Configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origins = ["localhost"],
            Timeout = 60000,
        };

        _attestation = new PublicKeyCredentialAttestation
        {
            Id = CredentialId,
            RawId = CredentialRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationResponse
            {
                ClientDataJson = "client-data",
                AttestationObject = "attestation-object",
                Transports = [AuthenticatorTransport.Internal],
            },
            Extensions = new AuthenticationExtensionsClientOutputs(),
        };

        _userEntity = new PublicKeyCredentialUserEntity
        {
            Id = Encoding.UTF8.GetBytes(UserName),
            Name = UserName,
            DisplayName = DisplayName,
        };

        _creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();
        _creationOptions.Challenge = [1, 2, 3, 4];
        _creationOptions.User = _userEntity;

        _sut = new Attestation(
            _attestationParametersValidatorMock.Object,
            _clientDataHandlerMock.Object,
            _attestationObjectHandlerMock.Object,
            _challengeGeneratorMock.Object,
            _userIdGeneratorMock.Object,
            _credentialRepositoryMock.Object,
            Options.Create(_fido2Configuration),
            NullLogger<Attestation>.Instance);
    }

    #region BeginRegistration Tests

    [Test]
    public void BeginRegistration_WhenParametersValidatorThrowsArgumentNullException_ThenThrowsArgumentNullException()
    {
        // Arrange
        _attestationParametersValidatorMock
            .Setup(a => a.Validate(It.IsAny<PublicKeyCredentialCreationOptionsRequest>()))
            .Throws<ArgumentNullException>();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(
            () => _sut.BeginRegistration(
                It.IsAny<PublicKeyCredentialCreationOptionsRequest>(),
                CancellationToken.None));
    }

    [Test]
    public async Task BeginRegistration_WhenAuthenticatorSelectionIsNull_ThenReturnsOptions()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = UserName,
            DisplayName = DisplayName,
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act
        var result = await _sut.BeginRegistration(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AuthenticatorSelection, Is.Not.Null);
        Assert.That(result.AuthenticatorSelection.AuthenticatorAttachment, Is.Null);
        Assert.That(result.AuthenticatorSelection.RequireResidentKey, Is.False);
        Assert.That(result.AuthenticatorSelection.UserVerification, Is.EqualTo(UserVerificationRequirement.Preferred));
    }

    [Test]
    public async Task BeginRegistration_WhenAttestationIsNull_ThenReturnsOptions()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = UserName,
            DisplayName = DisplayName,
            AuthenticatorSelection = null,
            Attestation = null,
        };

        // Act
        var result = await _sut.BeginRegistration(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Attestation, Is.EqualTo(AttestationConveyancePreference.None));
    }

    [Test]
    public async Task BeginRegistration_WhenCredentialExists_ThenReturnsOptions()
    {
        // Arrange
        var credential = new CredentialDescriptor
        {
            CredentialId = [7, 6, 1],
            Transports = ["internal", "usb"],
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(UserName, It.IsAny<CancellationToken>()))
            .ReturnsAsync([credential]);

        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = UserName,
            DisplayName = DisplayName,
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act
        var result = await _sut.BeginRegistration(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.ExcludeCredentials, Has.Length.EqualTo(1));
        Assert.That(result.ExcludeCredentials[0].Id, Is.EqualTo(credential.CredentialId));
        Assert.That(result.ExcludeCredentials[0].Type, Is.EqualTo(PublicKeyCredentialType.PublicKey));
    }

    [Test]
    [TestCase(AttestationConveyancePreference.None)]
    [TestCase(AttestationConveyancePreference.Indirect)]
    [TestCase(AttestationConveyancePreference.Direct)]
    [TestCase(AttestationConveyancePreference.Enterprise)]
    public async Task BeginRegistration_WhenRequestIsValid_ThenReturnsOptions(string attestationConveyancePreference)
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = UserName,
            DisplayName = DisplayName,
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = AuthenticatorAttachment.Platform,
                ResidentKey = ResidentKeyRequirement.Required,
                RequireResidentKey = true,
                UserVerification = UserVerificationRequirement.Required,
            },
            Attestation = attestationConveyancePreference,
        };

        // Act
        var result = await _sut.BeginRegistration(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.RelyingParty.Id, Is.EqualTo(_fido2Configuration.RelyingPartyId));
        Assert.That(result.RelyingParty.Name, Is.EqualTo(_fido2Configuration.RelyingPartyIdName));
        Assert.That(result.User.Name, Is.EqualTo(request.UserName));
        Assert.That(result.User.DisplayName, Is.EqualTo(request.DisplayName));
        Assert.That(result.User.Id, Is.EqualTo(request.UserName.FromBase64Url()));
        Assert.That(result.Challenge, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
        Assert.That(result.PublicKeyCredentialParams, Has.Length.EqualTo(12));
        Assert.That(result.Timeout, Is.EqualTo(60000));
        Assert.That(result.ExcludeCredentials, Has.Length.EqualTo(0));
        Assert.That(result.AuthenticatorSelection.AuthenticatorAttachment, Is.EqualTo(AuthenticatorAttachment.Platform));
        Assert.That(result.AuthenticatorSelection.ResidentKey, Is.EqualTo(ResidentKeyRequirement.Required));
        Assert.That(result.AuthenticatorSelection.RequireResidentKey, Is.True);
        Assert.That(result.AuthenticatorSelection.UserVerification, Is.EqualTo(UserVerificationRequirement.Required));
        Assert.That(result.Attestation, Is.EqualTo(attestationConveyancePreference));
    }

    #endregion

    #region CompleteRegistration Tests

    [Test]
    public void CompleteRegistration_WhenParametersValidatorThrowsArgumentNullException_ThenThrowsArgumentNullException()
    {
        // Arrange
        _attestationParametersValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<PublicKeyCredentialAttestation>(),
                It.IsAny<PublicKeyCredentialCreationOptions>()))
            .Throws<ArgumentNullException>();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() =>
            _sut.CompleteRegistration(
                _attestation,
                _creationOptions,
                CancellationToken.None));
    }

    [Test]
    public async Task CompleteRegistration_WhenParametersValidatorReturnsFailure_ThenReturnsFailure()
    {
        // Arrange
        _attestationParametersValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<PublicKeyCredentialAttestation>(),
                It.IsAny<PublicKeyCredentialCreationOptions>()))
            .Returns(AttestationCompleteResult.CreateFailure("Error"));

        // Act
        var result = await _sut.CompleteRegistration(
            _attestation,
            _creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Error"));
    }

    [Test]
    public async Task CompleteRegistration_WhenResponseIsNull_ThenReturnsFailure()
    {
        // Arrange
        _attestation.Response = null!;

        // Act
        var result = await _sut.CompleteRegistration(
            _attestation,
            _creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation response cannot be null"));
    }

    [Test]
    public async Task CompleteRegistration_WhenClientDataHasError_ThenReturnsFailure()
    {
        // Arrange
        _attestation.Response = new AuthenticatorAttestationResponse
        {
            ClientDataJson = "invalid-data",
            AttestationObject = "attestation-object",
            Transports = [],
        };

        _clientDataHandlerMock
            .Setup(a => a.HandleAttestation(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(new InternalResult<ClientData>("Client data validation failed"));

        // Act
        var result = await _sut.CompleteRegistration(
            _attestation,
            _creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Client data validation failed"));
    }

    [Test]
    public async Task CompleteRegistration_WhenAttestationObjectHasError_ThenReturnsFailure()
    {
        // Arrange
        _attestation.Response = new AuthenticatorAttestationResponse
        {
            ClientDataJson = "client-data",
            AttestationObject = "invalid-attestation",
            Transports = [],
        };

        _attestationObjectHandlerMock
            .Setup(a => a.Handle(
                It.IsAny<string>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InternalResult<AttestationObjectData>("Attestation object validation failed"));

        // Act
        var result = await _sut.CompleteRegistration(
            _attestation,
            _creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation object validation failed"));
    }

    [Test]
    public async Task CompleteRegistration_WhenCredentialAlreadyExists_ThenReturnsFailure()
    {
        // Arrange
        _credentialRepositoryMock
            .Setup(a => a.Exists(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.CompleteRegistration(
            _attestation,
            _creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Credential has already been registered"));
    }

    [Test]
    public async Task CompleteRegistration_WhenPublicKeyCredentialAttestationIsValid_ThenAddsCredentialAndReturnsSuccess()
    {
        // Arrange
        Credential? credential = null;
        _credentialRepositoryMock
            .Setup(a => a.Add(It.IsAny<Credential>(), It.IsAny<CancellationToken>()))
            .Callback<Credential, CancellationToken>((c, ct) => credential = c)
            .Returns(Task.CompletedTask);

        // Act
        var result = await _sut.CompleteRegistration(
            _attestation,
            _creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);

        Assert.That(credential, Is.Not.Null);
        Assert.That(credential!.CredentialId, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
        Assert.That(credential.CredentialPublicKey.KeyType, Is.EqualTo(2));
        Assert.That(credential.CredentialPublicKey.Algorithm, Is.EqualTo(-7));
        Assert.That(credential.CredentialPublicKey.Curve, Is.EqualTo(1));
        Assert.That(credential.CredentialPublicKey.XCoordinate, Is.EqualTo(new byte[] { 5, 6, 7, 8 }));
        Assert.That(credential.CredentialPublicKey.YCoordinate, Is.EqualTo(new byte[] { 9, 10, 11, 12 }));
        Assert.That(credential.SignCount, Is.EqualTo(1));
        Assert.That(credential.Transports, Is.EquivalentTo(["internal"]));
    }

    [Test]
    public async Task CompleteRegistration_WheniPhoneAndPublicKeyCredentialAttestationIsValid_ThenReturnsSuccess()
    {
        // Arrange
        var attestation = new PublicKeyCredentialAttestation
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
            Extensions = new AuthenticationExtensionsClientOutputs(),
        };

        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";
        _creationOptions.Challenge = Convert.FromBase64String($"{expectedChallenge}==");
        _creationOptions.User = _userEntity;

        // Act
        var result = await _sut.CompleteRegistration(
            attestation,
            _creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task CompleteRegistration_WhenWindowsAndPublicKeyCredentialAttestationIsValid_ThenReturnsSuccess()
    {
        // Arrange
        var attestation = new PublicKeyCredentialAttestation
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
            Extensions = new AuthenticationExtensionsClientOutputs(),
        };

        var expectedChallenge = "gsjJTjg3rcml3cfELwxAxQ";
        _creationOptions.Challenge = Convert.FromBase64String($"{expectedChallenge}==");
        _creationOptions.User = _userEntity;

        // Act
        var result = await _sut.CompleteRegistration(
            attestation,
            _creationOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    #endregion
}
