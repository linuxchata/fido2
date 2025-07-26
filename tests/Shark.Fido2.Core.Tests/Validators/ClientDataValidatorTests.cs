using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class ClientDataValidatorTests
{
    private ClientDataValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new ClientDataValidator(Options.Create(Fido2ConfigurationBuilder.Build()));
    }

    [Test]
    public void ValidateForAttestation_WhenClientDataValid_ThenReturnsValidResult()
    {
        // Arrange
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        // Act
        var result = _sut.ValidateForAttestation(clientDataModel, expectedChallenge);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateForAttestation_WhenClientDataValidWithTokenBinding_ThenReturnsValidResult()
    {
        // Arrange
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
            TokenBinding = new TokenBinding
            {
                Id = "7864716657891",
                Status = Domain.Enums.TokenBindingStatus.Present,
            },
        };

        // Act
        var result = _sut.ValidateForAttestation(clientDataModel, expectedChallenge);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateForAttestation_WhenTypeIsInvalid_ThenReturnsInvalidResult()
    {
        var expectedChallenge = "expected-challenge";

        var clientDataModel = new ClientData
        {
            Type = "invalid",
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        var result = _sut.ValidateForAttestation(clientDataModel, expectedChallenge);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Does.Contain("Client data type mismatch"));
    }

    [Test]
    public void ValidateForAttestation_WhenOriginIsMalformed_ThenReturnsInvalidResult()
    {
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = expectedChallenge,
            Origin = "invalid-uri",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        var result = _sut.ValidateForAttestation(clientDataModel, expectedChallenge);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Does.Contain("Invalid client data origin"));
    }

    [Test]
    public void ValidateForAttestation_WhenOriginIsNotAllowed_ThenReturnsInvalidResult()
    {
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = expectedChallenge,
            Origin = "https://not-allowed.com",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        var result = _sut.ValidateForAttestation(clientDataModel, expectedChallenge);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Does.Contain("Client data origin mismatch"));
    }

    [Test]
    public void ValidateForAttestation_WhenMissmatchedChallenge_ThenReturnsInvalidResult()
    {
        // Arrange
        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = "t2pJGIQ7Y4DXF2b98tnBjg",
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        // Act
        var result = _sut.ValidateForAttestation(clientDataModel, "1epJGYQ2Y9DXF1b98tnGwr==");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.Not.Null);
    }

    [Test]
    public void ValidateForAttestation_WhenMissingTokenBindingId_ThenReturnsInvalidResult()
    {
        // Arrange
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
            TokenBinding = new TokenBinding
            {
                Status = Domain.Enums.TokenBindingStatus.Present,
            },
        };

        // Act
        var result = _sut.ValidateForAttestation(clientDataModel, $"{expectedChallenge}==");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.Not.Null);
    }

    [Test]
    public void ValidateForAssertion_WhenClientDataValid_ThenReturnsValidResult()
    {
        // Arrange
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Get,
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        // Act
        var result = _sut.ValidateForAssertion(clientDataModel, expectedChallenge);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateForAssertion_WhenClientDataValidWithTokenBinding_ThenReturnsValidResult()
    {
        // Arrange
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Get,
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
            TokenBinding = new TokenBinding
            {
                Id = "7864716657891",
                Status = Domain.Enums.TokenBindingStatus.Present,
            },
        };

        // Act
        var result = _sut.ValidateForAssertion(clientDataModel, expectedChallenge);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public void ValidateForAssertion_WhenTypeIsInvalid_ThenReturnsInvalidResult()
    {
        var expectedChallenge = "expected-challenge";

        var clientDataModel = new ClientData
        {
            Type = "invalid",
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        var result = _sut.ValidateForAssertion(clientDataModel, expectedChallenge);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Does.Contain("Client data type mismatch"));
    }

    [Test]
    public void ValidateForAssertion_WhenOriginIsMalformed_ThenReturnsInvalidResult()
    {
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Get,
            Challenge = expectedChallenge,
            Origin = "invalid-uri",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        var result = _sut.ValidateForAssertion(clientDataModel, expectedChallenge);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Does.Contain("Invalid client data origin"));
    }

    [Test]
    public void ValidateForAssertion_WhenOriginIsNotAllowed_ThenReturnsInvalidResult()
    {
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Get,
            Challenge = expectedChallenge,
            Origin = "https://not-allowed.com",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        var result = _sut.ValidateForAssertion(clientDataModel, expectedChallenge);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Does.Contain("Client data origin mismatch"));
    }

    [Test]
    public void ValidateForAssertion_WhenMissmatchedChallenge_ThenReturnsInvalidResult()
    {
        // Arrange
        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Get,
            Challenge = "t2pJGIQ7Y4DXF2b98tnBjg",
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
        };

        // Act
        var result = _sut.ValidateForAssertion(clientDataModel, "1epJGYQ2Y9DXF1b98tnGwr==");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.Not.Null);
    }

    [Test]
    public void ValidateForAssertion_WhenMissingTokenBindingId_ThenReturnsInvalidResult()
    {
        // Arrange
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        var clientDataModel = new ClientData
        {
            Type = WebAuthnType.Get,
            Challenge = expectedChallenge,
            Origin = "https://localhost:4000",
            CrossOrigin = false,
            ClientDataHash = [],
            TokenBinding = new TokenBinding
            {
                Status = Domain.Enums.TokenBindingStatus.Present,
            },
        };

        // Act
        var result = _sut.ValidateForAssertion(clientDataModel, $"{expectedChallenge}==");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.Not.Null);
    }
}