using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Extensions;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests;

[TestFixture]
internal class AssertionTests
{
    private const string UserName = "UserName";
    private const string DisplayName = "DisplayName";
    private const string CredentialIdBase64 = "AQIDBA=="; // Base64 for [1,2,3,4]
    private const string CredentialRawId = "AQIDBA==";

    private readonly byte[] _credentialId = [1, 2, 3, 4];

    private Mock<IAssertionParametersValidator> _assertionParametersValidatorMock = null!;
    private Mock<IClientDataHandler> _clientDataHandlerMock = null!;
    private Mock<IAssertionObjectHandler> _assertionObjectHandlerMock = null!;
    private Mock<IUserHandlerValidator> _userHandlerValidatorMock = null!;
    private Mock<IChallengeGenerator> _challengeGeneratorMock = null!;
    private Mock<ICredentialRepository> _credentialRepositoryMock = null!;

    private byte[] _userHandle;
    private PublicKeyCredentialAssertion _publicKeyCredentialAssertion = null!;
    private PublicKeyCredentialRequestOptions _publicKeyCredentialRequestOptions = null!;
    private Fido2Configuration _fido2Configuration = null!;

    private Assertion _sut = null!;

    [SetUp]
    public void Setup()
    {
        _assertionParametersValidatorMock = new Mock<IAssertionParametersValidator>();
        _assertionParametersValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<PublicKeyCredentialAssertion>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Returns(AssertionCompleteResult.Create());

        _clientDataHandlerMock = new Mock<IClientDataHandler>();
        _clientDataHandlerMock
            .Setup(a => a.HandleAssertion(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(new InternalResult<ClientData>(ClientDataBuilder.BuildGet()));

        _assertionObjectHandlerMock = new Mock<IAssertionObjectHandler>();
        _assertionObjectHandlerMock
            .Setup(a => a.Handle(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<ClientData>(),
                It.IsAny<CredentialPublicKey>(),
                It.IsAny<AuthenticationExtensionsClientOutputs>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Returns(new InternalResult<AuthenticatorData>(new AuthenticatorData
            {
                AttestedCredentialData = new AttestedCredentialData(),
                SignCount = 2,
            }));

        _userHandlerValidatorMock = new Mock<IUserHandlerValidator>();
        _userHandlerValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<Credential>(),
                It.IsAny<PublicKeyCredentialAssertion>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Returns(ValidatorInternalResult.Valid());

        _challengeGeneratorMock = new Mock<IChallengeGenerator>();
        _challengeGeneratorMock.Setup(a => a.Get()).Returns([1, 2, 3, 4]);

        _credentialRepositoryMock = new Mock<ICredentialRepository>();
        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Credential?)null);

        _fido2Configuration = new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Test RP",
            Origins = ["localhost"],
            Timeout = 60000,
        };

        _publicKeyCredentialAssertion = new PublicKeyCredentialAssertion
        {
            Id = CredentialIdBase64,
            RawId = CredentialRawId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAssertionResponse
            {
                ClientDataJson = "test-client-data",
                AuthenticatorData = "test-authenticator-data",
                Signature = "test-signature",
            },
            Extensions = new AuthenticationExtensionsClientOutputs(),
        };

        _publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = [1, 2, 3, 4],
            RpId = _fido2Configuration.RelyingPartyId,
            Timeout = _fido2Configuration.Timeout,
            UserVerification = UserVerificationRequirement.Preferred,
        };

        _userHandle = Encoding.UTF8.GetBytes(UserName);

        _sut = new Assertion(
            _assertionParametersValidatorMock.Object,
            _clientDataHandlerMock.Object,
            _assertionObjectHandlerMock.Object,
            _userHandlerValidatorMock.Object,
            _challengeGeneratorMock.Object,
            _credentialRepositoryMock.Object,
            Options.Create(_fido2Configuration),
            NullLogger<Assertion>.Instance);
    }

    #region BeginAuthentication Tests

    [Test]
    public void BeginAuthentication_WhenParametersValidatorThrowsArgumentNullException_ThenThrowsArgumentNullException()
    {
        // Arrange
        _assertionParametersValidatorMock
            .Setup(a => a.Validate(It.IsAny<PublicKeyCredentialRequestOptionsRequest>()))
            .Throws<ArgumentNullException>();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(
            () => _sut.BeginAuthentication(
                It.IsAny<PublicKeyCredentialRequestOptionsRequest>(),
                It.IsAny<CancellationToken>()));
    }

    [Test]
    [TestCase(null!)]
    [TestCase("")]
    [TestCase("   ")]
    public async Task BeginAuthentication_WhenUsernameIsEmpty_ThenReturnsOptionsWithoutAllowCredentials(string username)
    {
        // Arrange
        var request = new PublicKeyCredentialRequestOptionsRequest
        {
            UserName = username,
            UserVerification = UserVerificationRequirement.Required,
        };

        // Act
        var result = await _sut.BeginAuthentication(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Challenge, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
        Assert.That(result.Timeout, Is.EqualTo(60000));
        Assert.That(result.RpId, Is.EqualTo("localhost"));
        Assert.That(result.AllowCredentials, Is.Null);
        Assert.That(result.Username, Is.EqualTo(username?.Trim()));
        Assert.That(result.UserVerification, Is.EqualTo(UserVerificationRequirement.Required));
    }

    [Test]
    public async Task BeginAuthentication_WhenUsernameIsProvided_ThenReturnsOptionsWithAllowCredentials()
    {
        // Arrange
        var request = new PublicKeyCredentialRequestOptionsRequest
        {
            UserName = UserName,
            UserVerification = UserVerificationRequirement.Required,
        };

        var credentials = new List<CredentialDescriptor>
        {
            new()
            {
                CredentialId = [5, 6, 7, 8],
                Transports = ["internal", "usb"],
            },
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(UserName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credentials);

        // Act
        var result = await _sut.BeginAuthentication(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Challenge, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
        Assert.That(result.Timeout, Is.EqualTo(60000));
        Assert.That(result.RpId, Is.EqualTo("localhost"));
        Assert.That(result.AllowCredentials, Is.Not.Null);
        Assert.That(result.AllowCredentials!, Has.Length.EqualTo(1));
        Assert.That(result.AllowCredentials![0].Id, Is.EqualTo(new byte[] { 5, 6, 7, 8 }));
        Assert.That(result.AllowCredentials![0].Transports, Is.EquivalentTo([AuthenticatorTransport.Internal, AuthenticatorTransport.Usb]));
        Assert.That(result.Username, Is.EqualTo(UserName));
        Assert.That(result.UserVerification, Is.EqualTo(UserVerificationRequirement.Required));
    }

    [Test]
    public async Task BeginAuthentication_WhenUserVerificationIsNull_ThenReturnsOptionsWithPreferredUserVerification()
    {
        // Arrange
        var request = new PublicKeyCredentialRequestOptionsRequest
        {
            UserName = UserName,
            UserVerification = null,
        };

        // Act
        var result = await _sut.BeginAuthentication(request, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.UserVerification, Is.EqualTo(UserVerificationRequirement.Preferred));
    }

    #endregion

    #region CompleteAuthentication Tests

    [Test]
    public void CompleteAuthentication_WhenParametersValidatorThrowsArgumentNullException_ThenThrowsArgumentNullException()
    {
        // Arrange
        _assertionParametersValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<PublicKeyCredentialAssertion>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Throws<ArgumentNullException>();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() =>
            _sut.CompleteAuthentication(
                _publicKeyCredentialAssertion,
                _publicKeyCredentialRequestOptions,
                It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task CompleteAuthentication_WhenParametersValidatorReturnsFailure_ThenReturnsFailure()
    {
        // Arrange
        _assertionParametersValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<PublicKeyCredentialAssertion>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Returns(AssertionCompleteResult.CreateFailure("Error"));

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Error"));
    }

    [Test]
    public async Task CompleteAuthentication_WhenResponseIsNull_ThenReturnsFailure()
    {
        // Arrange
        _publicKeyCredentialAssertion.Response = null!;

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Assertion response cannot be null"));
    }

    [Test]
    public async Task CompleteAuthentication_WhenCredentialIdNotInAllowCredentials_ThenReturnsFailure()
    {
        // Arrange
        var requestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = [],
            AllowCredentials =
            [
                new PublicKeyCredentialDescriptor
                {
                    Id = [5, 6, 7, 8], // Different credential identifiers
                    Transports = [AuthenticatorTransport.Internal],
                },
            ],
        };

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            requestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Assertion response does not contain expected credential"));
    }

    [Test]
    public async Task CompleteAuthentication_WhenCredentialNotFound_ThenReturnsFailure()
    {
        // Arrange
        var requestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = [],
            AllowCredentials =
            [
                new PublicKeyCredentialDescriptor
                {
                    Id = _credentialId, // Matching credential identifiers
                    Transports = [AuthenticatorTransport.Internal],
                },
            ],
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Credential?)null);

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            requestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Registered credential is not found"));
    }

    [Test]
    public async Task CompleteAuthentication_WhenUserValidationFails_ThenReturnsFailure()
    {
        // Arrange
        var credential = new Credential
        {
            CredentialId = _credentialId,
            UserHandle = _userHandle,
            UserName = UserName,
            UserDisplayName = DisplayName,
            CredentialPublicKey = new CredentialPublicKey(),
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _userHandlerValidatorMock
            .Setup(a => a.Validate(credential, _publicKeyCredentialAssertion, _publicKeyCredentialRequestOptions))
            .Returns(ValidatorInternalResult.Invalid("User is not the owner of the credential"));

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User is not the owner of the credential"));
    }

    [Test]
    public async Task CompleteAuthentication_WhenCredentialPublicKeyIsNull_ThenReturnsFailure()
    {
        // Arrange
        var credential = new Credential
        {
            CredentialId = _credentialId,
            UserHandle = _userHandle,
            UserName = UserName,
            UserDisplayName = DisplayName,
            CredentialPublicKey = null!,
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _userHandlerValidatorMock
            .Setup(a => a.Validate(credential, _publicKeyCredentialAssertion, _publicKeyCredentialRequestOptions))
            .Returns(ValidatorInternalResult.Valid());

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Registered credential's public key is not found"));
    }

    [Test]
    public async Task CompleteAuthentication_WhenClientDataHasError_ThenReturnsFailure()
    {
        // Arrange
        var credential = new Credential
        {
            CredentialId = _credentialId,
            UserHandle = _userHandle,
            UserName = UserName,
            UserDisplayName = DisplayName,
            CredentialPublicKey = new CredentialPublicKey(),
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _clientDataHandlerMock
            .Setup(a => a.HandleAssertion(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(new InternalResult<ClientData>("Client data cannot be read"));

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Client data cannot be read"));
    }

    [Test]
    public async Task CompleteAuthentication_WhenAssertionObjectHasError_ThenReturnsFailure()
    {
        // Arrange
        var credential = new Credential
        {
            CredentialId = _credentialId,
            UserHandle = _userHandle,
            UserName = UserName,
            UserDisplayName = DisplayName,
            CredentialPublicKey = new CredentialPublicKey(),
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _assertionObjectHandlerMock
            .Setup(a => a.Handle(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<ClientData>(),
                It.IsAny<CredentialPublicKey>(),
                It.IsAny<AuthenticationExtensionsClientOutputs>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Returns(new InternalResult<AuthenticatorData>("Assertion object validation failed"));

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Assertion object validation failed"));
    }

    [Test]
    public async Task CompleteAuthentication_WhenSignCountIsLessOrEqualToStoredSignCount_ThenReturnsFailure()
    {
        // Arrange
        var credential = new Credential
        {
            CredentialId = _credentialId,
            UserHandle = _userHandle,
            UserName = UserName,
            UserDisplayName = DisplayName,
            CredentialPublicKey = new CredentialPublicKey(),
            SignCount = 3, // Higher than the authenticator's sign count (2)
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("The authenticator's signature counter value is less than or equal to the previously stored count, indicating that the device may have been cloned or duplicated."));
    }

    [Test]
    public async Task CompleteAuthentication_WhenAssertionIsValid_ThenUpdatesSignCountAndReturnsSuccess()
    {
        // Arrange
        var credential = new Credential
        {
            CredentialId = _credentialId,
            UserHandle = _userHandle,
            UserName = UserName,
            UserDisplayName = DisplayName,
            CredentialPublicKey = new CredentialPublicKey(),
            SignCount = 1, // Lower than the authenticator's sign count (2)
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);

        _credentialRepositoryMock.Verify(
            a => a.UpdateSignCount(credential.CredentialId, 2, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteAuthentication_WhenBothSignCountsAreZero_ThenReturnsSuccess()
    {
        // Arrange
        var credential = new Credential
        {
            CredentialId = _credentialId,
            UserHandle = _userHandle,
            UserName = UserName,
            UserDisplayName = DisplayName,
            CredentialPublicKey = new CredentialPublicKey(),
            SignCount = 0, // Zero sign count
        };

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _assertionObjectHandlerMock
            .Setup(a => a.Handle(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<ClientData>(),
                It.IsAny<CredentialPublicKey>(),
                It.IsAny<AuthenticationExtensionsClientOutputs>(),
                It.IsAny<PublicKeyCredentialRequestOptions>()))
            .Returns(new InternalResult<AuthenticatorData>(new AuthenticatorData
            {
                AttestedCredentialData = new AttestedCredentialData(),
                SignCount = 0, // Zero sign count
            }));

        // Act
        var result = await _sut.CompleteAuthentication(
            _publicKeyCredentialAssertion,
            _publicKeyCredentialRequestOptions,
            CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);

        // Verify that UpdateSignCount was not called
        _credentialRepositoryMock.Verify(
            a => a.UpdateSignCount(It.IsAny<byte[]>(), It.IsAny<uint>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    #endregion
}
