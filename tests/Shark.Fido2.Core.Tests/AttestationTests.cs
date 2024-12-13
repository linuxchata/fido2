using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests;

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
        _attestationObjectHandlerMock = new Mock<IAttestationObjectHandler>();
        var challengeGeneratorMock = new Mock<IChallengeGenerator>();
        _credentialRepositoryMock = new Mock<ICredentialRepository>();

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
    public async Task Complete_WhenPublicKeyCredentialValid_ThenReturnsSuccess()
    {
        // Arrange
        var publicKeyCredential = new PublicKeyCredential
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
            Type = "public-key",
        };
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";

        _clientDataHandlerMock
            .Setup(a => a.Handle(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(new InternalResult<ClientData>(new ClientData()));

        _attestationObjectHandlerMock
            .Setup(a => a.Handle(It.IsAny<string>()))
            .Returns(new InternalResult<AttestationObjectData>(new AttestationObjectData { AuthenticatorData = new AuthenticatorData() }));

        _credentialRepositoryMock
            .Setup(a => a.Get(It.IsAny<byte[]>()))
            .ReturnsAsync((Credential?)null);

        // Act
        var result = await _sut.Complete(publicKeyCredential, $"{expectedChallenge}==");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Status, Is.EqualTo(ResponseStatus.Ok));
        Assert.That(result.Message, Is.Null);
    }
}