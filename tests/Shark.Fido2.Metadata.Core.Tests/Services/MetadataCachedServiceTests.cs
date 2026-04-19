using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Mappers;
using Shark.Fido2.Metadata.Core.Models;
using Shark.Fido2.Metadata.Core.Services;

namespace Shark.Fido2.Metadata.Core.Tests.Services;

[TestFixture]
internal class MetadataCachedServiceTests
{
    private const string Description = nameof(Description);
    private const string CacheKey = "mds_payload";
    private const int DefaultDistributedCacheExpirationInMinutes = 30;

    private Guid _aaguid;
    private DateTime _nextUpdate;
    private MetadataBlobPayloadEntry _metadataBlobPayloadEntry;

    private Mock<IMetadataService> _metadataServiceMock;
    private Mock<IDistributedCache> _distributedCacheMock;
    private Mock<IMemoryCache> _memoryCacheMock;
    private Mock<TimeProvider> _timeProviderMock;

    private MetadataCachedService _sut;

    [SetUp]
    public void Setup()
    {
        _aaguid = Guid.NewGuid();
        _nextUpdate = DateTime.UtcNow.AddDays(30);

        var metadataStatement = new MetadataStatement
        {
            Description = Description,
            ProtocolFamily = "fido2",
            Upv = [new UnifiedProtocolVersion { Major = 1, Minor = 1 }],
            AuthenticationAlgorithms = ["secp256r1_ecdsa_sha256_raw"],
            PublicKeyAlgAndEncodings = ["cose"],
            AttestationTypes = ["basic_full"],
            UserVerificationDetails = [],
            KeyProtection = ["software"],
            MatcherProtection = ["software"],
            TcDisplay = ["none"],
            AttestationRootCertificates = ["MII..."],
        };
        _metadataBlobPayloadEntry = new MetadataBlobPayloadEntry
        {
            Aaguid = _aaguid,
            MetadataStatement = metadataStatement,
            StatusReports = [],
            TimeOfLastStatusChange = DateTime.UtcNow.ToString(CultureInfo.InvariantCulture),
        };

        _metadataServiceMock = new Mock<IMetadataService>();
        _distributedCacheMock = new Mock<IDistributedCache>();

        var memoryCacheEntry = new Mock<ICacheEntry>();
        memoryCacheEntry.SetupAllProperties();
        _memoryCacheMock = new Mock<IMemoryCache>();
        _memoryCacheMock
            .Setup(x => x.CreateEntry(It.IsAny<string>()))
            .Returns(memoryCacheEntry.Object);

        _timeProviderMock = new Mock<TimeProvider>();
        _timeProviderMock.Setup(x => x.GetUtcNow()).Returns(DateTimeOffset.UtcNow);

        _sut = new MetadataCachedService(
            _metadataServiceMock.Object,
            _distributedCacheMock.Object,
            _memoryCacheMock.Object,
            _timeProviderMock.Object);
    }

    [Test]
    public void Get_WhenDistributedCacheThrowsException_ThenRethrowsException()
    {
        // Arrange
        var expectedException = new InvalidOperationException("Cache error");

        object? nullValue = null!;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<string>(), out nullValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ThrowsAsync(expectedException);

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(() => _sut.Get(_aaguid, CancellationToken.None));
    }

    [Test]
    public void Get_WhenMetadataServiceThrowsException_ThenRethrowsException()
    {
        // Arrange
        var expectedException = new HttpRequestException("Service error");

        object? nullValue = null!;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<string>(), out nullValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync((byte[]?)null!);

        _metadataServiceMock
            .Setup(x => x.Get(CancellationToken.None))
            .ThrowsAsync(expectedException);

        // Act & Assert
        Assert.ThrowsAsync<HttpRequestException>(() => _sut.Get(_aaguid, CancellationToken.None));
    }

    [Test]
    public async Task Get_WhenItemIsInMemoryCache_ThenReturnsItemFromMemoryCache()
    {
        // Arrange
        var expectedValue = _metadataBlobPayloadEntry.ToDomain();

        object? cachedItem = expectedValue;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<object>(), out cachedItem))
            .Returns(true);

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.EqualTo(expectedValue));
    }

    [Test]
    public async Task Get_WhenEmptyItemIsNotInMemoryCacheButInDistributedCache_ThenReturnsNull()
    {
        // Arrange
        var serializedPayload = "[]";

        object? nullValue = null!;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<string>(), out nullValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync(Encoding.UTF8.GetBytes(serializedPayload));

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Never);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                CacheKey,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                CancellationToken.None),
            Times.Never);

        _metadataServiceMock.Verify(x => x.Get(CancellationToken.None), Times.Never);
    }

    [Test]
    public async Task Get_WhenItemIsNotInMemoryCacheButInDistributedCache_ThenCachesItemInMemoryCacheAndReturnsItem()
    {
        var serializedPayload = JsonSerializer.Serialize(new[] { _metadataBlobPayloadEntry });

        object? nullValue = null!;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<string>(), out nullValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync(Encoding.UTF8.GetBytes(serializedPayload));

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Aaguid, Is.EqualTo(_aaguid));
        Assert.That(result.Description, Is.EqualTo(Description));

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Once);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                CacheKey,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                CancellationToken.None),
            Times.Never);

        _metadataServiceMock.Verify(x => x.Get(CancellationToken.None), Times.Never);
    }

    [Test]
    public async Task Get_WhenItemNotInCaches_ThenCachesItemInCachesAndReturnsItem()
    {
        // Arrange
        var metadataBlobPayload = new MetadataBlobPayload
        {
            Payload = [_metadataBlobPayloadEntry],
            NextUpdate = _nextUpdate,
            Number = 1,
        };

        object? nullValue = null!;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<string>(), out nullValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync((byte[]?)null!);

        _metadataServiceMock
            .Setup(x => x.Get(CancellationToken.None))
            .ReturnsAsync(metadataBlobPayload);

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Aaguid, Is.EqualTo(_aaguid));
        Assert.That(result.Description, Is.EqualTo(Description));

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Once);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                CacheKey,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                CancellationToken.None),
            Times.Once);

        _metadataServiceMock.Verify(x => x.Get(CancellationToken.None), Times.Once);
    }

    [Test]
    public async Task Get_WhenNextUpdateIsToday_ThenUsesDefaultExpirationTime()
    {
        // Arrange
        var today = DateTime.UtcNow.Date;
        var todayNextUpdate = today.AddHours(12);
        var nowTime = DateTimeOffset.UtcNow;

        var metadataBlobPayload = new MetadataBlobPayload
        {
            Payload = [_metadataBlobPayloadEntry],
            NextUpdate = todayNextUpdate,
            Number = 1,
        };

        object? nullValue = null!;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<string>(), out nullValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync((byte[]?)null!);

        _metadataServiceMock
            .Setup(x => x.Get(CancellationToken.None))
            .ReturnsAsync(metadataBlobPayload);

        _timeProviderMock
            .Setup(x => x.GetUtcNow())
            .Returns(nowTime);

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Once);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                CacheKey,
                It.IsAny<byte[]>(),
                It.Is<DistributedCacheEntryOptions>(options =>
                    options.AbsoluteExpiration!.Value <= nowTime.AddMinutes(DefaultDistributedCacheExpirationInMinutes + 1) &&
                    options.AbsoluteExpiration!.Value >= nowTime.AddMinutes(DefaultDistributedCacheExpirationInMinutes - 1)),
                CancellationToken.None),
            Times.Once);

        _metadataServiceMock.Verify(x => x.Get(CancellationToken.None), Times.Once);
    }

    [Test]
    public async Task Get_WhenNextUpdateIsFuture_ThenUsesNextUpdateAsExpiration()
    {
        // Arrange
        var futureNextUpdate = DateTime.UtcNow.AddDays(7);

        var metadataBlobPayload = new MetadataBlobPayload
        {
            Payload = [_metadataBlobPayloadEntry],
            NextUpdate = futureNextUpdate,
            Number = 1,
        };

        object? nullValue = null!;

        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<string>(), out nullValue))
            .Returns(false);

        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, CancellationToken.None))
            .ReturnsAsync((byte[]?)null!);

        _metadataServiceMock
            .Setup(x => x.Get(CancellationToken.None))
            .ReturnsAsync(metadataBlobPayload);

        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Once);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                CacheKey,
                It.IsAny<byte[]>(),
                It.Is<DistributedCacheEntryOptions>(options =>
                    options.AbsoluteExpiration == new DateTimeOffset(futureNextUpdate)),
                CancellationToken.None),
            Times.Once);

        _metadataServiceMock.Verify(x => x.Get(CancellationToken.None), Times.Once);
    }

    [Test]
    public async Task Get_WhenCalledConcurrently_ThenPopulatesDistributedCacheOnlyOnce()
    {
        // Arrange
        var metadataBlobPayload = new MetadataBlobPayload
        {
            Payload = [_metadataBlobPayloadEntry],
            NextUpdate = _nextUpdate,
            Number = 1,
        };

        object? nullValue = null!;
        _memoryCacheMock
            .Setup(x => x.TryGetValue(It.IsAny<string>(), out nullValue))
            .Returns(false);

        var callCount = 0;
        _metadataServiceMock
            .Setup(x => x.Get(It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                Interlocked.Increment(ref callCount);
                await Task.Delay(100, CancellationToken.None);
                return metadataBlobPayload;
            });

        byte[]? cachedBytes = null;
        _distributedCacheMock
            .Setup(x => x.GetAsync(CacheKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => cachedBytes);

        _distributedCacheMock
            .Setup(x => x.SetAsync(
                CacheKey,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, byte[], DistributedCacheEntryOptions, CancellationToken>(
                (_, value, _, _) => cachedBytes = value)
            .Returns(Task.CompletedTask);

        // Act
        var tasks = Enumerable.Range(0, 10).Select(_ => _sut.Get(_aaguid, CancellationToken.None)).ToList();
        await Task.WhenAll(tasks);

        // Assert
        Assert.That(callCount, Is.EqualTo(1));
        _metadataServiceMock.Verify(x => x.Get(It.IsAny<CancellationToken>()), Times.Once);
        _distributedCacheMock.Verify(
            x => x.SetAsync(
                CacheKey,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }
}
