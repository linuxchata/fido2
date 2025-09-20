using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class UserHandlerValidatorTests
{
    private const string DefaultUserHandleBase64 = "dXNlckhhbmRsZQ=="; // "userHandle" in base64
    private const string DifferentUserHandleBase64 = "ZGlmZmVyZW50VXNlckhhbmRsZQ=="; // "differentUserHandle" in base64
    private const string DefaultUserName = "johndoe@example.com";
    private const string DifferentUsername = "johnoliver@example.com";

    private UserHandlerValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new UserHandlerValidator();
    }

    [Test]
    public void Validate_WhenAllowCredentialsPresentAndUserHandleMatches_ThenReturnsValidResult()
    {
        // Arrange
        var credential = CreateCredential();
        var publicKeyCredentialAssertion = CreatePublicKeyCredentialAssertion();
        var requestOptions = CreatePublicKeyCredentialRequestOptions();

        // Act
        var result = _sut.Validate(credential, publicKeyCredentialAssertion, requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenAllowCredentialsPresentAndUserHandleDoesNotMatch_ThenReturnsInvalidResult()
    {
        // Arrange
        var credential = CreateCredential();
        var publicKeyCredentialAssertion = CreatePublicKeyCredentialAssertion(DifferentUserHandleBase64);
        var requestOptions = CreatePublicKeyCredentialRequestOptions();

        // Act
        var result = _sut.Validate(credential, publicKeyCredentialAssertion, requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User is not the owner of the credential"));
    }

    [Test]
    public void Validate_WhenAllowCredentialsPresentAndUserHandleEmptyAndUsernameMatches_ThenReturnsValidResult()
    {
        // Arrange
        var credential = CreateCredential();
        var publicKeyCredentialAssertion = CreatePublicKeyCredentialAssertion(null); // Empty user handle
        var requestOptions = CreatePublicKeyCredentialRequestOptions();

        // Act
        var result = _sut.Validate(credential, publicKeyCredentialAssertion, requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void Validate_WhenAllowCredentialsPresentAndUserHandleEmptyAndUsernameIsNullOrEmptyInRequestOptions_ThenReturnsValidResult(string? username)
    {
        // Arrange
        var credential = CreateCredential();
        var publicKeyCredentialAssertion = CreatePublicKeyCredentialAssertion(null); // Empty user handle
        var requestOptions = CreatePublicKeyCredentialRequestOptions(true, username!);

        // Act
        var result = _sut.Validate(credential, publicKeyCredentialAssertion, requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void Validate_WhenAllowCredentialsPresentAndUserHandleEmptyAndUsernameDoesNotMatch_ThenReturnsInvalidResult()
    {
        // Arrange
        var credential = CreateCredential();
        var publicKeyCredentialAssertion = CreatePublicKeyCredentialAssertion(null); // Empty user handle
        var requestOptions = CreatePublicKeyCredentialRequestOptions(true, DifferentUsername);

        // Act
        var result = _sut.Validate(credential, publicKeyCredentialAssertion, requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User is not the owner of the credential"));
    }

    [Test]
    public void Validate_WhenAllowCredentialsNotPresentAndUserHandleEmpty_ThenReturnsInvalidResult()
    {
        // Arrange
        var credential = CreateCredential();
        var publicKeyCredentialAssertion = CreatePublicKeyCredentialAssertion(null); // Empty user handle
        var requestOptions = CreatePublicKeyCredentialRequestOptions(false);

        // Act
        var result = _sut.Validate(credential, publicKeyCredentialAssertion, requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User handle is not present"));
    }

    [Test]
    public void Validate_WhenAllowCredentialsNotPresentAndUserHandleDoesNotMatch_ThenReturnsInvalidResult()
    {
        // Arrange
        var credential = CreateCredential();
        var publicKeyCredentialAssertion = CreatePublicKeyCredentialAssertion(DifferentUserHandleBase64);
        var requestOptions = CreatePublicKeyCredentialRequestOptions(false);

        // Act
        var result = _sut.Validate(credential, publicKeyCredentialAssertion, requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("User is not the owner of the credential"));
    }

    [Test]
    public void Validate_WhenAllowCredentialsNotPresentAndUserHandleMatches_ThenReturnsValidResult()
    {
        // Arrange
        var credential = CreateCredential();
        var publicKeyCredentialAssertion = CreatePublicKeyCredentialAssertion();
        var requestOptions = CreatePublicKeyCredentialRequestOptions(false);

        // Act
        var result = _sut.Validate(credential, publicKeyCredentialAssertion, requestOptions);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    private static Credential CreateCredential(string userName = DefaultUserName)
    {
        return new Credential
        {
            CredentialId = [1, 2, 3, 4],
            UserHandle = Convert.FromBase64String(DefaultUserHandleBase64),
            UserName = userName,
            UserDisplayName = "John Doe",
            CredentialPublicKey = new CredentialPublicKey(),
        };
    }

    private static PublicKeyCredentialAssertion CreatePublicKeyCredentialAssertion(
        string? userHandle = DefaultUserHandleBase64)
    {
        return new PublicKeyCredentialAssertion
        {
            Id = "testId",
            RawId = "testRawId",
            Type = "public-key",
            Response = new AuthenticatorAssertionResponse
            {
                ClientDataJson = "{}",
                AuthenticatorData = "data",
                Signature = "signature",
                UserHandle = userHandle,
            },
            Extensions = new AuthenticationExtensionsClientOutputs(),
        };
    }

    private static PublicKeyCredentialRequestOptions CreatePublicKeyCredentialRequestOptions(
        bool includeAllowCredentials = true,
        string userName = DefaultUserName)
    {
        return new PublicKeyCredentialRequestOptions
        {
            Challenge = [5, 6, 7, 8],
            AllowCredentials = includeAllowCredentials
                ? [new PublicKeyCredentialDescriptor { Id = [1, 2, 3, 4] }]
                : null,
            Username = userName,
        };
    }
}
