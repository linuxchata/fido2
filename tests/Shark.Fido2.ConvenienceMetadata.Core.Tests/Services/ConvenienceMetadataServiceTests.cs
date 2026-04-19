using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions.Repositories;
using Shark.Fido2.ConvenienceMetadata.Core.Models;
using Shark.Fido2.ConvenienceMetadata.Core.Services;

namespace Shark.Fido2.ConvenienceMetadata.Core.Tests.Services;

[TestFixture]
internal class ConvenienceMetadataServiceTests
{
    private Mock<IHttpClientRepository> _httpClientRepositoryMock;
    private Mock<IConvenienceMetadataReaderService> _convenienceMetadataReaderServiceMock;
    private ConvenienceMetadataService _sut = null!;

    [SetUp]
    public void Setup()
    {
        _httpClientRepositoryMock = new Mock<IHttpClientRepository>();
        _convenienceMetadataReaderServiceMock = new Mock<IConvenienceMetadataReaderService>();

        _sut = new ConvenienceMetadataService(
            _httpClientRepositoryMock.Object,
            _convenienceMetadataReaderServiceMock.Object,
            NullLogger<ConvenienceMetadataService>.Instance);
    }

    [Test]
    public async Task Get_WhenRepositoryThrowsException_ThenReturnsNull()
    {
        // Arrange
        _httpClientRepositoryMock
            .Setup(x => x.GetConvenienceMetadataBlob(CancellationToken.None))
            .ThrowsAsync(new HttpRequestException());

        // Act
        var result = await _sut.Get(CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenReaderServiceThrowsException_ThenReturnsNull()
    {
        // Arrange
        var blob = "some-blob";
        _httpClientRepositoryMock
            .Setup(x => x.GetConvenienceMetadataBlob(CancellationToken.None))
            .ReturnsAsync(blob);

        _convenienceMetadataReaderServiceMock
            .Setup(x => x.Read(blob))
            .Throws(new InvalidDataException());

        // Act
        var result = await _sut.Get(CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenCalled_ThenReturnsResultFromReader()
    {
        // Arrange
        var blob = "sample-blob";
        var expectedPayload = new ConvenienceMetadataPayload
        {
            Entries = new Dictionary<string, System.Text.Json.JsonElement>(),
        };

        _httpClientRepositoryMock
            .Setup(x => x.GetConvenienceMetadataBlob(CancellationToken.None))
            .ReturnsAsync(blob);

        _convenienceMetadataReaderServiceMock
            .Setup(x => x.Read(blob))
            .Returns(expectedPayload);

        // Act
        var result = await _sut.Get(CancellationToken.None);

        // Assert
        Assert.That(result, Is.EqualTo(expectedPayload));
        _httpClientRepositoryMock.Verify(x => x.GetConvenienceMetadataBlob(CancellationToken.None), Times.Once);
        _convenienceMetadataReaderServiceMock.Verify(x => x.Read(blob), Times.Once);
    }
}
