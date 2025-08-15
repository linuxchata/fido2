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
    private const string KeyPrefix = "md";
    private const int DefaultDistributedCacheExpirationInMinutes = 30;

    private Guid _aaguid;
    private CancellationToken _cancellationToken;
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
        _cancellationToken = CancellationToken.None;
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
            TimeOfLastStatusChange = DateTime.UtcNow.ToString(),
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
            .Setup(x => x.GetAsync(KeyPrefix, _cancellationToken))
            .ThrowsAsync(expectedException);

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(() => _sut.Get(_aaguid, _cancellationToken));
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
            .Setup(x => x.GetAsync(KeyPrefix, _cancellationToken))
            .ReturnsAsync((byte[]?)null!);

        _metadataServiceMock
            .Setup(x => x.Get(_cancellationToken))
            .ThrowsAsync(expectedException);

        // Act & Assert
        Assert.ThrowsAsync<HttpRequestException>(() => _sut.Get(_aaguid, _cancellationToken));
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
        var result = await _sut.Get(_aaguid, _cancellationToken);

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
            .Setup(x => x.GetAsync(KeyPrefix, _cancellationToken))
            .ReturnsAsync(Encoding.UTF8.GetBytes(serializedPayload));

        // Act
        var result = await _sut.Get(_aaguid, _cancellationToken);

        // Assert
        Assert.That(result, Is.Null);

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Never);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                KeyPrefix,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                _cancellationToken),
            Times.Never);

        _metadataServiceMock.Verify(x => x.Get(It.IsAny<CancellationToken>()), Times.Never);
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
            .Setup(x => x.GetAsync(KeyPrefix, _cancellationToken))
            .ReturnsAsync(Encoding.UTF8.GetBytes(serializedPayload));

        // Act
        var result = await _sut.Get(_aaguid, _cancellationToken);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Aaguid, Is.EqualTo(_aaguid));
        Assert.That(result.Description, Is.EqualTo(Description));

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Once);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                KeyPrefix,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                _cancellationToken),
            Times.Never);

        _metadataServiceMock.Verify(x => x.Get(It.IsAny<CancellationToken>()), Times.Never);
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
            .Setup(x => x.GetAsync(KeyPrefix, _cancellationToken))
            .ReturnsAsync((byte[]?)null!);

        _metadataServiceMock
            .Setup(x => x.Get(_cancellationToken))
            .ReturnsAsync(metadataBlobPayload);

        // Act
        var result = await _sut.Get(_aaguid, _cancellationToken);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Aaguid, Is.EqualTo(_aaguid));
        Assert.That(result.Description, Is.EqualTo(Description));

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Once);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                KeyPrefix,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                _cancellationToken),
            Times.Once);

        _metadataServiceMock.Verify(x => x.Get(It.IsAny<CancellationToken>()), Times.Once);
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
            .Setup(x => x.GetAsync(KeyPrefix, _cancellationToken))
            .ReturnsAsync((byte[]?)null!);

        _metadataServiceMock
            .Setup(x => x.Get(_cancellationToken))
            .ReturnsAsync(metadataBlobPayload);

        _timeProviderMock
            .Setup(x => x.GetUtcNow())
            .Returns(nowTime);

        // Act
        var result = await _sut.Get(_aaguid, _cancellationToken);

        // Assert
        Assert.That(result, Is.Not.Null);

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Once);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                KeyPrefix,
                It.IsAny<byte[]>(),
                It.Is<DistributedCacheEntryOptions>(options =>
                    options.AbsoluteExpiration!.Value <= nowTime.AddMinutes(DefaultDistributedCacheExpirationInMinutes + 1) &&
                    options.AbsoluteExpiration!.Value >= nowTime.AddMinutes(DefaultDistributedCacheExpirationInMinutes - 1)),
                _cancellationToken),
            Times.Once);

        _metadataServiceMock.Verify(x => x.Get(It.IsAny<CancellationToken>()), Times.Once);
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
            .Setup(x => x.GetAsync(KeyPrefix, _cancellationToken))
            .ReturnsAsync((byte[]?)null!);

        _metadataServiceMock
            .Setup(x => x.Get(_cancellationToken))
            .ReturnsAsync(metadataBlobPayload);

        // Act
        var result = await _sut.Get(_aaguid, _cancellationToken);

        // Assert
        Assert.That(result, Is.Not.Null);

        _memoryCacheMock.Verify(x => x.CreateEntry(It.IsAny<string>()), Times.Once);

        _distributedCacheMock.Verify(
            x => x.SetAsync(
                KeyPrefix,
                It.IsAny<byte[]>(),
                It.Is<DistributedCacheEntryOptions>(options =>
                    options.AbsoluteExpiration == new DateTimeOffset(futureNextUpdate)),
                _cancellationToken),
            Times.Once);

        _metadataServiceMock.Verify(x => x.Get(It.IsAny<CancellationToken>()), Times.Once);
    }
}