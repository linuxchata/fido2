using System.Text;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
public class AttestationParametersValidatorTests
{
    private const string UserName = "UserName";
    private const string DisplayName = "DisplayName";

    private PublicKeyCredentialAttestation _publicKeyCredentialAttestation = null!;
    private PublicKeyCredentialCreationOptions _publicKeyCredentialCreationOptions = null!;

    private AttestationParametersValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _publicKeyCredentialAttestation = new PublicKeyCredentialAttestation
        {
            Id = "AQIDBA==",
            RawId = "AQIDBA==",
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationResponse
            {
                ClientDataJson = "client-data",
                AttestationObject = "attestation-object",
                Transports = [AuthenticatorTransport.Internal],
            },
            Extensions = new AuthenticationExtensionsClientOutputs(),
        };

        var publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity
        {
            Id = Encoding.UTF8.GetBytes(UserName),
            Name = UserName,
            DisplayName = DisplayName,
        };

        _publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();
        _publicKeyCredentialCreationOptions.Challenge = [1, 2, 3, 4];
        _publicKeyCredentialCreationOptions.User = publicKeyCredentialUserEntity;

        _sut = new AttestationParametersValidator();
    }

    [Test]
    public void Validate_WhenRequestIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        PublicKeyCredentialCreationOptionsRequest? request = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(request!));
    }

    [Test]
    public void Validate_WhenUserNameIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = null!,
            DisplayName = DisplayName,
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(request));
    }

    [Test]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenUserNameIsEmpty_ThenThrowsArgumentException(string userName)
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = userName,
            DisplayName = DisplayName,
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(request));
    }

    [Test]
    public void Validate_WhenDisplayNameIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = UserName,
            DisplayName = null!,
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(request));
    }

    [Test]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenDisplayNameIsEmpty_ThenThrowsArgumentException(string displayName)
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = UserName,
            DisplayName = displayName,
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(request));
    }

    [Test]
    public void Validate_WhenUserNameIsLongerThanAllowedLength_ThenThrowsArgumentException()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = new string('*', 65),
            DisplayName = DisplayName,
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(request));
    }

    [Test]
    public void Validate_WhenDisplayNameIsLongerThanAllowedLength_ThenThrowsArgumentException()
    {
        // Arrange
        var request = new PublicKeyCredentialCreationOptionsRequest
        {
            UserName = UserName,
            DisplayName = new string('*', 65),
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sut.Validate(request));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialAttestationIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        PublicKeyCredentialAttestation? publicKeyCredentialAttestation = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(publicKeyCredentialAttestation!, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenIdIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        _publicKeyCredentialAttestation.Id = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenIdIsEmpty_ThenThrowsArgumentException(string id)
    {
        // Arrange
        _publicKeyCredentialAttestation.Id = id;

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenRawIdIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        _publicKeyCredentialAttestation.RawId = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenRawIdIsEmpty_ThenThrowsArgumentException(string rawId)
    {
        // Arrange
        _publicKeyCredentialAttestation.RawId = rawId;

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialCreationOptionsIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        PublicKeyCredentialCreationOptions? creationOptions = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, creationOptions!));
    }

    [Test]
    public void Validate_WhenRelyingPartyIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        _publicKeyCredentialCreationOptions.RelyingParty = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenUserIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        _publicKeyCredentialCreationOptions.User = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialParamsAreNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        _publicKeyCredentialCreationOptions.PublicKeyCredentialParams = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenExcludeCredentialsAreNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        _publicKeyCredentialCreationOptions.ExcludeCredentials = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenAuthenticatorSelectionIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        _publicKeyCredentialCreationOptions.AuthenticatorSelection = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenAttestationIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        _publicKeyCredentialCreationOptions.Attestation = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenAttestationIsEmpty_ThenThrowsArgumentException(string attestation)
    {
        // Arrange
        _publicKeyCredentialCreationOptions.Attestation = attestation;

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialAttestationIdIsInvalid_ThenReturnsFailure()
    {
        // Arrange
        _publicKeyCredentialAttestation.Id = "aaa";

        // Act
        var result = _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation identifier is not Base64URL-encoded"));
    }

    [Test]
    public void Validate_WhenPublicKeyCredentialAttestationTypeIsInvalid_ThenReturnsFailure()
    {
        // Arrange
        _publicKeyCredentialAttestation.Type = "invalid-type";

        // Act
        var result = _sut.Validate(_publicKeyCredentialAttestation, _publicKeyCredentialCreationOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Attestation type is not set to \"public-key\""));
    }
}
