using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.Handlers;

[TestFixture]
internal class ClientDataHandlerTests
{
    private ClientDataHandler _sut = null!;
    private Mock<IClientDataValidator> _clientDataValidatorMock = null!;

    [SetUp]
    public void Setup()
    {
        _clientDataValidatorMock = new Mock<IClientDataValidator>();
        _clientDataValidatorMock
            .Setup(a => a.Validate(It.IsAny<ClientData>(), It.IsAny<string>()))
            .Returns(ValidatorInternalResult.Valid());

        _sut = new ClientDataHandler(_clientDataValidatorMock.Object);
    }

    [Test]
    public void Handle_WhenClientDataJsonValid_ThenReturnsInternalResult()
    {
        // Arrange
        var clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidDJwSkdJUTdZNERYRjJiOTh0bkJqZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==";
        var expectedChallenge = "t2pJGIQ7Y4DXF2b98tnBjg";
        var expectedOrigin = "https://localhost:4000";

        // Act
        var result = _sut.Handle(clientDataJson, $"{expectedChallenge}==");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);

        _clientDataValidatorMock.Verify(
            a => a.Validate(
                It.Is<ClientData>(c =>
                    c != null &&
                    c.Type == WebAuthnType.Create &&
                    c.Challenge == expectedChallenge &&
                    c.Origin == expectedOrigin &&
                    c.CrossOrigin == false),
                It.IsAny<string>()),
            Times.Once);
    }

    [Test]
    public void Handle_WhenClientDataJsonValidAndWithTokenBindingWithNonSupportedStatus_ThenReturnsInternalResult()
    {
        // Arrange
        var clientDataJson = "eyJjaGFsbGVuZ2UiOiJ1Vlg4OElnUmEwU1NyTUlSVF9xN2NSY2RmZ2ZSQnhDZ25fcGtwVUFuWEpLMnpPYjMwN3dkMU9MWFEwQXVOYU10QlIzYW1rNkhZenAtX1Z4SlRQcHdHdyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidG9rZW5CaW5kaW5nIjp7InN0YXR1cyI6Im5vdC1zdXBwb3J0ZWQifSwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9";
        var expectedChallenge = "uVX88IgRa0SSrMIRT_q7cRcdfgfRBxCgn_pkpUAnXJK2zOb307wd1OLXQ0AuNaMtBR3amk6HYzp-_VxJTPpwGw";
        var expectedOrigin = "https://webauthn.org";

        // Act
        var result = _sut.Handle(clientDataJson, expectedChallenge);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);

        _clientDataValidatorMock.Verify(
            a => a.Validate(
                It.Is<ClientData>(c =>
                    c != null &&
                    c.Type == WebAuthnType.Create &&
                    c.Challenge == expectedChallenge &&
                    c.Origin == expectedOrigin &&
                    c.CrossOrigin == false),
                It.IsAny<string>()),
            Times.Once);
    }

    [Test]
    public void Handle_WhenClientDataJsonValidAndWithTokenBindingWithSupportedStatus_ThenReturnsInternalResult()
    {
        // Arrange
        var clientDataJson = "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIndrNkxxRVhBTUFacHFjVFlsWTJ5b3I1RGppeUlfYjFneTluRE90Q0IxeUdZbm1fNFdHNFVrMjRGQXI3QXhUT0ZmUU1laWdrUnhPVExaTnJMeEN2Vl9RIiwNCgkib3JpZ2luIiA6ICJodHRwczovL3dlYmF1dGhuLm9yZyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9";
        var expectedChallenge = "wk6LqEXAMAZpqcTYlY2yor5DjiyI_b1gy9nDOtCB1yGYnm_4WG4Uk24FAr7AxTOFfQMeigkRxOTLZNrLxCvV_Q";
        var expectedOrigin = "https://webauthn.org";

        // Act
        var result = _sut.Handle(clientDataJson, expectedChallenge);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);

        _clientDataValidatorMock.Verify(
            a => a.Validate(
                It.Is<ClientData>(c =>
                    c != null &&
                    c.Type == WebAuthnType.Create &&
                    c.Challenge == expectedChallenge &&
                    c.Origin == expectedOrigin &&
                    c.CrossOrigin == false),
                It.IsAny<string>()),
            Times.Once);
    }
}