using Microsoft.Extensions.Options;
using Moq;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests;

public class AttestationServiceTests
{
    private IAttestationService _sut = null!;

    [SetUp]
    public void Setup()
    {
        var challengeGeneratorMock = new Mock<IChallengeGenerator>();

        var fido2ConfigurationMock = new Fido2Configuration
        {
            Origin = "localhost",
        };

        _sut = new AttestationService(challengeGeneratorMock.Object, Options.Create(fido2ConfigurationMock));
    }

    [Test]
    public void Complete_When_Then()
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

        // Act
        _sut.Complete(publicKeyCredential, "t2pJGIQ7Y4DXF2b98tnBjg==");

        // Assert

    }
}