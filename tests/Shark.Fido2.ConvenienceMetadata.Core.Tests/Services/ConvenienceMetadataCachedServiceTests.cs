using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.ConvenienceMetadata.Core.Constants;
using Shark.Fido2.ConvenienceMetadata.Core.Domain;
using Shark.Fido2.ConvenienceMetadata.Core.Models;
using Shark.Fido2.ConvenienceMetadata.Core.Services;

namespace Shark.Fido2.ConvenienceMetadata.Core.Tests.Services;

[TestFixture]
internal class ConvenienceMetadataCachedServiceTests
{
    private const string CacheKey = "cmds_payload";
    private readonly Guid _aaguid = Guid.NewGuid();

    private Mock<IConvenienceMetadataService> _convenienceMetadataServiceMock;
    private Mock<IDistributedCache> _distributedCacheMock;
    private Mock<IMemoryCache> _memoryCacheMock;
    private Mock<TimeProvider> _timeProviderMock;

    private ConvenienceMetadataCachedService _sut = null!;

    [SetUp]
    public void Setup()
    {
        _convenienceMetadataServiceMock = new Mock<IConvenienceMetadataService>();
        _distributedCacheMock = new Mock<IDistributedCache>();

        var memoryCacheEntry = new Mock<ICacheEntry>();
        memoryCacheEntry.SetupAllProperties();
        _memoryCacheMock = new Mock<IMemoryCache>();
        _memoryCacheMock
            .Setup(x => x.CreateEntry(It.IsAny<object>()))
            .Returns(memoryCacheEntry.Object);

        _timeProviderMock = new Mock<TimeProvider>();
        _timeProviderMock.Setup(x => x.GetUtcNow()).Returns(DateTimeOffset.UtcNow);

        _sut = new ConvenienceMetadataCachedService(
            _convenienceMetadataServiceMock.Object,
            _distributedCacheMock.Object,
            _memoryCacheMock.Object,
            _timeProviderMock.Object);
    }

    [Test]
    public async Task Get_WhenItemIsInMemoryCache_ThenReturnsItemFromMemoryCache()
    {
        // Arrange
        var expectedItem = new ConvenienceMetadataPayloadItem
        {
            Aaguid = _aaguid,
            FriendlyNames = new Dictionary<string, string>
            {
                [Culture.EnglishUs] = "Test"
            }
        };
        object? cachedValue = expectedItem;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<object>(), out cachedValue))
            .Returns(true);

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.EqualTo(expectedItem));
        Assert.That(result.GetDefaultName(), Is.EqualTo("Test"));
        _distributedCacheMock.Verify(x => x.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task Get_WhenItemNotInMemoryCacheButInDistributedCache_ThenCachesItemInMemoryCacheAndReturnsItem()
    {
        // Arrange
        object? nullMemoryCacheValue = null;
        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<object>(), out nullMemoryCacheValue))
            .Returns(false);

        var entries = new Dictionary<string, object>
        {
            [_aaguid.ToString()] = new { friendlyNames = new Dictionary<string, string> { [Culture.EnglishUs] = "Test" } },
        };
        var serializedEntries = JsonSerializer.Serialize(entries);
        var bytes = System.Text.Encoding.UTF8.GetBytes(serializedEntries);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync(bytes);

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Aaguid, Is.EqualTo(_aaguid));
        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<object>()), Times.Once);
    }

    [Test]
    public async Task Get_WhenItemNotInCaches_ThenCachesItemInCachesAndReturnsItem()
    {
        // Arrange
        object? nullMemoryCacheValue = null;
        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<object>(), out nullMemoryCacheValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync((byte[]?)null);

        var serviceEntries = new Dictionary<string, JsonElement>();
        var entryJson = JsonSerializer.SerializeToElement(
            new { friendlyNames = new Dictionary<string, string> { [Culture.EnglishUs] = "Test" } });
        serviceEntries[_aaguid.ToString()] = entryJson;

        var servicePayload = new ConvenienceMetadataPayload { Entries = serviceEntries };

        _convenienceMetadataServiceMock
            .Setup(x => x.Get(CancellationToken.None))
            .ReturnsAsync(servicePayload);

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Aaguid, Is.EqualTo(_aaguid));

        _convenienceMetadataServiceMock.Verify(x => x.Get(CancellationToken.None), Times.Once);
        _distributedCacheMock.Verify(
            x => x.SetAsync(
                CacheKey,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                CancellationToken.None),
            Times.Once);
        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<object>()), Times.Once);
    }

    [Test]
    public async Task Get_WhenServiceReturnsNull_ThenReturnsNull()
    {
        // Arrange
        object? nullMemoryCacheValue = null;
        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<object>(), out nullMemoryCacheValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync((byte[]?)null);

        _convenienceMetadataServiceMock
            .Setup(x => x.Get(CancellationToken.None))
            .ReturnsAsync((ConvenienceMetadataPayload?)null);

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }
}
