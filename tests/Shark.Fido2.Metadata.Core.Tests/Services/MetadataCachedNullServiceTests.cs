using Shark.Fido2.Metadata.Core.Services;

namespace Shark.Fido2.Metadata.Core.Tests.Services;

[TestFixture]
internal class MetadataCachedNullServiceTests
{
    private Guid _aaguid;
    private CancellationToken _cancellationToken;

    private MetadataCachedNullService _sut;

    [SetUp]
    public void Setup()
    {
        _aaguid = Guid.NewGuid();
        _cancellationToken = CancellationToken.None;

        _sut = new MetadataCachedNullService();
    }

    [Test]
    public async Task Get_WhenAaguidIsValid_ThenReturnsNull()
    {
        // Act
        var result = await _sut.Get(_aaguid, _cancellationToken);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenAaguidIsEmptyGuid_ThenReturnsNull()
    {
        // Act
        var result = await _sut.Get(Guid.Empty, _cancellationToken);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenAaguidIsNewGuid_ThenReturnsNull()
    {
        // Arrange
        var newGuid = Guid.NewGuid();

        // Act
        var result = await _sut.Get(newGuid, _cancellationToken);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenCalledMultipleTimes_ThenReturnsNull()
    {
        // Act
        var result1 = await _sut.Get(_aaguid, _cancellationToken);
        var result2 = await _sut.Get(_aaguid, _cancellationToken);
        var result3 = await _sut.Get(Guid.NewGuid(), _cancellationToken);

        // Assert
        Assert.That(result1, Is.Null);
        Assert.That(result2, Is.Null);
        Assert.That(result3, Is.Null);
    }
}