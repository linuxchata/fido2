using Shark.Fido2.Metadata.Core.Services;

namespace Shark.Fido2.Metadata.Core.Tests.Services;

[TestFixture]
internal class MetadataCachedNullServiceTests
{
    private Guid _aaguid;

    private MetadataCachedNullService _sut;

    [SetUp]
    public void Setup()
    {
        _aaguid = Guid.NewGuid();

        _sut = new MetadataCachedNullService();
    }

    [Test]
    public async Task Get_WhenAaguidIsValid_ThenReturnsNull()
    {
        // Act
        var result = await _sut.Get(_aaguid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenAaguidIsEmptyGuid_ThenReturnsNull()
    {
        // Act
        var result = await _sut.Get(Guid.Empty, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenAaguidIsNewGuid_ThenReturnsNull()
    {
        // Arrange
        var newGuid = Guid.NewGuid();

        // Act
        var result = await _sut.Get(newGuid, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenCalledMultipleTimes_ThenReturnsNull()
    {
        // Act
        var result1 = await _sut.Get(_aaguid, CancellationToken.None);
        var result2 = await _sut.Get(_aaguid, CancellationToken.None);
        var result3 = await _sut.Get(Guid.NewGuid(), CancellationToken.None);

        // Assert
        Assert.That(result1, Is.Null);
        Assert.That(result2, Is.Null);
        Assert.That(result3, Is.Null);
    }
}