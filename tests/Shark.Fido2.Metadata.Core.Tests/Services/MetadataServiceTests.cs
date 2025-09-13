using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Models;
using Shark.Fido2.Metadata.Core.Services;

namespace Shark.Fido2.Metadata.Core.Tests.Services;

[TestFixture]
internal class MetadataServiceTests
{
    private Mock<X509Certificate2> _rootCertificateMock;
    private CancellationToken _cancellationToken;

    private Mock<IHttpClientRepository> _httpClientRepositoryMock;
    private Mock<IMetadataReaderService> _metadataReaderServiceMock;

    private MetadataService _sut = null!;

    [SetUp]
    public void Setup()
    {
        _rootCertificateMock = new Mock<X509Certificate2>();
        _cancellationToken = CancellationToken.None;

        _httpClientRepositoryMock = new Mock<IHttpClientRepository>();
        _metadataReaderServiceMock = new Mock<IMetadataReaderService>();

        _sut = new MetadataService(
            _httpClientRepositoryMock.Object,
            _metadataReaderServiceMock.Object,
            NullLogger<MetadataService>.Instance);
    }

    [Test]
    public void Get_WhenHttpClientRepositoryThrowsException_ThenRethrowsException()
    {
        // Arrange
        var expectedException = new HttpRequestException("Network error");

        _httpClientRepositoryMock
            .Setup(x => x.GetRootCertificate(_cancellationToken))
            .ThrowsAsync(expectedException);

        // Act & Assert
        Assert.ThrowsAsync<HttpRequestException>(() => _sut.Get(_cancellationToken));
    }

    [Test]
    public void Get_WhenMetadataReaderServiceThrowsException_ThenRethrowsException()
    {
        // Arrange
        var metadataBlob = "jwt-token-blob";
        var expectedException = new InvalidOperationException("Validation failed");

        _httpClientRepositoryMock
            .Setup(x => x.GetRootCertificate(_cancellationToken))
            .ReturnsAsync(_rootCertificateMock.Object);

        _httpClientRepositoryMock
            .Setup(x => x.GetMetadataBlob(_cancellationToken))
            .ReturnsAsync(metadataBlob);

        _metadataReaderServiceMock
            .Setup(x => x.ValidateAndRead(metadataBlob, _rootCertificateMock.Object, _cancellationToken))
            .ThrowsAsync(expectedException);

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(() => _sut.Get(_cancellationToken));
    }

    [Test]
    public void Get_WhenGetMetadataBlobThrowsException_ThenRethrowsException()
    {
        // Arrange
        var expectedException = new HttpRequestException("Metadata blob download failed");

        _httpClientRepositoryMock
            .Setup(x => x.GetRootCertificate(_cancellationToken))
            .ReturnsAsync(_rootCertificateMock.Object);

        _httpClientRepositoryMock
            .Setup(x => x.GetMetadataBlob(_cancellationToken))
            .ThrowsAsync(expectedException);

        // Act & Assert
        Assert.ThrowsAsync<HttpRequestException>(() => _sut.Get(_cancellationToken));
    }

    [Test]
    public async Task Get_WhenCalled_ThenCallsAllDependencies()
    {
        // Arrange
        var metadataBlob = "jwt-token-blob";
        var expectedPayload = new MetadataBlobPayload
        {
            Payload = [],
            NextUpdate = DateTime.UtcNow.AddDays(30),
            Number = 1,
        };

        _httpClientRepositoryMock
            .Setup(x => x.GetRootCertificate(_cancellationToken))
            .ReturnsAsync(_rootCertificateMock.Object);

        _httpClientRepositoryMock
            .Setup(x => x.GetMetadataBlob(_cancellationToken))
            .ReturnsAsync(metadataBlob);

        _metadataReaderServiceMock
            .Setup(x => x.ValidateAndRead(metadataBlob, _rootCertificateMock.Object, _cancellationToken))
            .ReturnsAsync(expectedPayload);

        // Act
        var result = await _sut.Get(_cancellationToken);

        // Assert
        Assert.That(result, Is.EqualTo(expectedPayload));

        _httpClientRepositoryMock.Verify(x => x.GetRootCertificate(_cancellationToken), Times.Once);
        _httpClientRepositoryMock.Verify(x => x.GetMetadataBlob(_cancellationToken), Times.Once);
        _metadataReaderServiceMock.Verify(
            x => x.ValidateAndRead(metadataBlob, _rootCertificateMock.Object, _cancellationToken), Times.Once);
    }

    [Test]
    public async Task Get_WhenEmptyPayload_ThenReturnsEmptyPayload()
    {
        // Arrange
        var metadataBlob = "empty-blob";
        var expectedPayload = new MetadataBlobPayload
        {
            Payload = [],
            NextUpdate = DateTime.UtcNow.AddDays(1),
            Number = 0,
        };

        _httpClientRepositoryMock
            .Setup(x => x.GetRootCertificate(_cancellationToken))
            .ReturnsAsync(_rootCertificateMock.Object);

        _httpClientRepositoryMock
            .Setup(x => x.GetMetadataBlob(_cancellationToken))
            .ReturnsAsync(metadataBlob);

        _metadataReaderServiceMock
            .Setup(x => x.ValidateAndRead(metadataBlob, _rootCertificateMock.Object, _cancellationToken))
            .ReturnsAsync(expectedPayload);

        // Act
        var result = await _sut.Get(_cancellationToken);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Payload, Is.Empty);
        Assert.That(result.NextUpdate, Is.EqualTo(expectedPayload.NextUpdate));
        Assert.That(result.Number, Is.Zero);
    }

    [Test]
    public async Task Get_WhenValidPayload_ThenReturnsExpectedResult()
    {
        // Arrange
        var metadataBlob = "jwt-token-blob";
        var expectedPayload = new MetadataBlobPayload
        {
            Payload =
            [
                new MetadataBlobPayloadEntry
                {
                    Aaguid = Guid.NewGuid(),
                    StatusReports = [],
                    TimeOfLastStatusChange = DateTime.UtcNow.ToString(),
                },
            ],
            NextUpdate = DateTime.UtcNow.AddDays(30),
            Number = 42,
        };

        _httpClientRepositoryMock
            .Setup(x => x.GetRootCertificate(_cancellationToken))
            .ReturnsAsync(_rootCertificateMock.Object);

        _httpClientRepositoryMock
            .Setup(x => x.GetMetadataBlob(_cancellationToken))
            .ReturnsAsync(metadataBlob);

        _metadataReaderServiceMock
            .Setup(x => x.ValidateAndRead(metadataBlob, _rootCertificateMock.Object, _cancellationToken))
            .ReturnsAsync(expectedPayload);

        // Act
        var result = await _sut.Get(_cancellationToken);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Payload, Has.Count.EqualTo(1));
        Assert.That(result.NextUpdate, Is.EqualTo(expectedPayload.NextUpdate));
        Assert.That(result.Number, Is.EqualTo(42));
        Assert.That(result.Payload[0].Aaguid, Is.EqualTo(expectedPayload.Payload[0].Aaguid));
    }
}