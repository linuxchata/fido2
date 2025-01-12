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
            Id = "InvZ7_ZJi4-xByVUxjUwSknCRCtBui8nZUMUpQVNXXk",
            RawId = "InvZ7/ZJi4+xByVUxjUwSknCRCtBui8nZUMUpQVNXXk=",
            Response = new AuthenticatorAttestationResponse
            {
                AttestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAACAie9nv9kmLj7EHJVTGNTBKScJEK0G6LydlQxSlBU1deaQBAwM5AQAgWQEAtMJIZwd8jZ5hacwaNfGkAMBLVlj4HkFcQpYiSsyigauVSdfMvzLi+w5trCHdvjK4lIU6odXm6nIKqtCk98sHoCSlRU884TEhIED5E/uh0dw0WlfApP8h9Fdi+6qMpqlqe0K836TDYHpuo9ntp/Pt3HqrK2zKIFI9FiyRj+XTL06wUe88qIKE2r2JRkWVl8sGptsPr2elC4nG9WudlFOHN7nlfsmGdSwjTIZhWvPeT4ErpncjS5TK1Vz9auddr97FeWD8lNZET1sgNav6T9D4kIei+aVJi8G8vtUGReByUiBpJM9PvUkjbDLFfwSg3kK0P6EY7uu/5AGGd+1PHV+2rSFDAQAB",
                ClientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOWlLTGRyVUFTeHJtT0hCTm44SElEQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
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
}