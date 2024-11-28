using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Core.Results;

namespace Shark.Fido2.Core.Tests.Handlers;

public class ClientDataHandlerTests
{
    private ClientDataHandler _sut = null!;
    private Mock<IClientDataValidator> _clientDataValidatorMock = null!;

    [SetUp]
    public void Setup()
    {
        _clientDataValidatorMock = new Mock<IClientDataValidator>();

        _sut = new ClientDataHandler(_clientDataValidatorMock.Object);
    }

    [Test]
    public void Handle_WhenClientDataJsonValid_ThenReturnsNull()
    {
        // Arrange
        var clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidDJwSkdJUTdZNERYRjJiOTh0bkJqZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==";
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";
        var expectedOrigin = "https://localhost:4000";

        _clientDataValidatorMock
            .Setup(a => a.Validate(It.IsAny<ClientDataModel?>(), It.IsAny<string>()))
            .Returns(ValidatorInternalResult.Valid());

        // Act
        var result = _sut.Handle(clientDataJson, $"{expectedChallenge}==");

        // Assert
        Assert.That(result, Is.Not.Null);

        _clientDataValidatorMock.Verify(
            a => a.Validate(
                It.Is<ClientDataModel?>(c =>
                    c != null &&
                    c.Type == WebauthnType.Create &&
                    c.Challenge == expectedChallenge &&
                    c.Origin == expectedOrigin &&
                    c.CrossOrigin == false),
                It.IsAny<string>()),
            Times.Once);
    }
}