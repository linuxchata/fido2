using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Shark.Fido2.Domain;

namespace Shark.Fido2.InMemory.Tests;

[TestFixture]
internal class CredentialRepositoryTests
{
    private const string UserName = "UserName";
    private const string UserDisplayName = "UserDisplayName";

    private static readonly byte[] CredentialId = [1, 2, 3, 4];
    private static readonly byte[] CredentialId2 = [9, 10, 11, 12];
    private static readonly byte[] UserHandle = [5, 6, 7, 8];

    private IDistributedCache _cache = null!;
    private FakeTimeProvider _timeProvider = null!;
    private CredentialRepository _sut = null!;

    [SetUp]
    public void Setup()
    {
        var options = Options.Create(new MemoryDistributedCacheOptions());
        _cache = new MemoryDistributedCache(options);

        _timeProvider = new FakeTimeProvider();
        _timeProvider.SetUtcNow(new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero));

        _sut = new CredentialRepository(_cache, _timeProvider);
    }

    #region Get Tests

    [Test]
    public async Task Get_WhenCredentialIdIsNull_ThenReturnsNull()
    {
        // Act
        var result = await _sut.Get((byte[]?)null, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenCredentialIdIsEmpty_ThenReturnsNull()
    {
        // Act
        var result = await _sut.Get([], CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenCredentialDoesNotExist_ThenReturnsNull()
    {
        // Act
        var result = await _sut.Get(CredentialId, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Get_WhenCredentialExists_ThenReturnsCredential()
    {
        // Arrange
        var credential = CreateTestCredential();
        await _sut.Add(credential, CancellationToken.None);

        // Act
        var result = await _sut.Get(CredentialId, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.CredentialId, Is.EqualTo(CredentialId));
        Assert.That(result.UserHandle, Is.EqualTo(UserHandle));
        Assert.That(result.UserName, Is.EqualTo(UserName));
        Assert.That(result.UserDisplayName, Is.EqualTo(UserDisplayName));
        Assert.That(result.SignCount, Is.Zero);
        Assert.That(result.CredentialPublicKey, Is.Not.Null);
    }

    [Test]
    [TestCase(null!)]
    [TestCase("")]
    [TestCase("   ")]
    public async Task Get_WhenUserNameIsNullOrEmpty_ThenReturnsEmptyList(string userName)
    {
        // Act
        var result = await _sut.Get(userName, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.Empty);
    }

    [Test]
    public async Task Get_WhenUserHasNoCredentials_ThenReturnsEmptyList()
    {
        // Act
        var result = await _sut.Get(UserName, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.Empty);
    }

    [Test]
    public async Task Get_WhenUserHasSingleCredential_ThenReturnsListWithOneCredential()
    {
        // Arrange
        var credential = CreateTestCredential();
        await _sut.Add(credential, CancellationToken.None);

        // Act
        var result = await _sut.Get(UserName, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Has.Count.EqualTo(1));
        Assert.That(result[0].CredentialId, Is.EqualTo(CredentialId));
        Assert.That(result[0].Transports, Is.Not.Null);
        Assert.That(result[0].Transports, Has.Length.EqualTo(2));
    }

    [Test]
    public async Task Get_WhenUserHasMultipleCredentials_ThenReturnsListWithAllCredentials()
    {
        // Arrange
        var credential1 = CreateTestCredential();
        var credential2 = CreateTestCredential(CredentialId2);
        await _sut.Add(credential1, CancellationToken.None);
        await _sut.Add(credential2, CancellationToken.None);

        // Act
        var result = await _sut.Get(UserName, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Has.Count.EqualTo(2));
        Assert.That(result.Select(c => c.CredentialId), Contains.Item(CredentialId));
        Assert.That(result.Select(c => c.CredentialId), Contains.Item(CredentialId2));
    }

    #endregion

    #region Exists Tests

    [Test]
    public async Task Exists_WhenCredentialIdIsNull_ThenReturnsFalse()
    {
        // Act
        var result = await _sut.Exists((byte[]?)null, CancellationToken.None);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task Exists_WhenCredentialIdIsEmpty_ThenReturnsFalse()
    {
        // Act
        var result = await _sut.Exists([], CancellationToken.None);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task Exists_WhenCredentialDoesNotExist_ThenReturnsFalse()
    {
        // Act
        var result = await _sut.Exists(CredentialId, CancellationToken.None);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task Exists_WhenCredentialExists_ThenReturnsTrue()
    {
        // Arrange
        var credential = CreateTestCredential();
        await _sut.Add(credential, CancellationToken.None);

        // Act
        var result = await _sut.Exists(CredentialId, CancellationToken.None);

        // Assert
        Assert.That(result, Is.True);
    }

    #endregion

    #region Add Tests

    [Test]
    public void Add_WhenCredentialIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => _sut.Add(null!, CancellationToken.None));
    }

    [Test]
    public void Add_WhenCredentialIdIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var credential = CreateTestCredential();
        credential.CredentialId = null!;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => _sut.Add(credential, CancellationToken.None));
    }

    [Test]
    public void Add_WhenUserNameIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var credential = CreateTestCredential();
        credential.UserName = null!;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => _sut.Add(credential, CancellationToken.None));
    }

    [Test]
    public void Add_WhenUserNameIsEmpty_ThenThrowsArgumentException()
    {
        // Arrange
        var credential = CreateTestCredential();
        credential.UserName = string.Empty;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(() => _sut.Add(credential, CancellationToken.None));
    }

    [Test]
    public void Add_WhenUserHandleIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var credential = CreateTestCredential();
        credential.UserHandle = null!;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => _sut.Add(credential, CancellationToken.None));
    }

    [Test]
    public void Add_WhenCredentialPublicKeyIsNull_ThenThrowsArgumentNullException()
    {
        // Arrange
        var credential = CreateTestCredential();
        credential.CredentialPublicKey = null!;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => _sut.Add(credential, CancellationToken.None));
    }

    [Test]
    public async Task Add_WhenCredentialIsValid_ThenAddsCredentialToCache()
    {
        // Arrange
        var credential = CreateTestCredential();

        // Act
        await _sut.Add(credential, CancellationToken.None);

        // Assert
        var result = await _sut.Get(CredentialId, CancellationToken.None);
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.CredentialId, Is.EqualTo(CredentialId));
    }

    [Test]
    public async Task Add_WhenCredentialIsValid_ThenSetsCreatedAtTimestamp()
    {
        // Arrange
        var credential = CreateTestCredential();
        var expectedTime = _timeProvider.GetUtcNow().UtcDateTime;

        // Act
        await _sut.Add(credential, CancellationToken.None);

        // Assert
        var result = await _sut.Get(CredentialId, CancellationToken.None);
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.CreatedAt, Is.EqualTo(expectedTime));
    }

    [Test]
    public async Task Add_WhenAddingMultipleCredentialsForSameUser_ThenAllCredentialsAreStored()
    {
        // Arrange
        var credential1 = CreateTestCredential();
        var credential2 = CreateTestCredential(CredentialId2);

        // Act
        await _sut.Add(credential1, CancellationToken.None);
        await _sut.Add(credential2, CancellationToken.None);

        // Assert
        var credentials = await _sut.Get(UserName, CancellationToken.None);
        Assert.That(credentials, Has.Count.EqualTo(2));
    }

    #endregion

    #region UpdateSignCount Tests

    [Test]
    public void UpdateSignCount_WhenCredentialDoesNotExist_ThenNotThrowException()
    {
        // Act & Assert
        Assert.DoesNotThrowAsync(() => _sut.UpdateSignCount(CredentialId, 42, CancellationToken.None));
    }

    [Test]
    public async Task UpdateSignCount_WhenCredentialExists_ThenUpdatesSignCount()
    {
        // Arrange
        var credential = CreateTestCredential();
        await _sut.Add(credential, CancellationToken.None);

        _timeProvider.Advance(TimeSpan.FromHours(1));
        var expectedTime = _timeProvider.GetUtcNow().UtcDateTime;

        // Act
        await _sut.UpdateSignCount(CredentialId, 42, CancellationToken.None);

        // Assert
        var result = await _sut.Get(CredentialId, CancellationToken.None);
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.SignCount, Is.EqualTo(42));
        Assert.That(result!.UpdatedAt, Is.EqualTo(expectedTime));
        Assert.That(result!.LastUsedAt, Is.EqualTo(expectedTime));
    }

    #endregion

    #region UpdateLastUsedAt Tests

    [Test]
    public void UpdateLastUsedAt_WhenCredentialDoesNotExist_ThenNotThrowException()
    {
        // Act & Assert
        Assert.DoesNotThrowAsync(() => _sut.UpdateLastUsedAt(CredentialId, CancellationToken.None));
    }

    [Test]
    public async Task UpdateLastUsedAt_WhenCredentialExists_ThenUpdatesLastUsedAtTimestamp()
    {
        // Arrange
        var credential = CreateTestCredential();
        await _sut.Add(credential, CancellationToken.None);

        _timeProvider.Advance(TimeSpan.FromHours(2));
        var expectedTime = _timeProvider.GetUtcNow().UtcDateTime;

        // Act
        await _sut.UpdateLastUsedAt(CredentialId, CancellationToken.None);

        // Assert
        var result = await _sut.Get(CredentialId, CancellationToken.None);
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.LastUsedAt, Is.EqualTo(expectedTime));
    }

    #endregion

    private static Credential CreateTestCredential(byte[]? credentialId = null)
    {
        return new Credential
        {
            CredentialId = credentialId ?? CredentialId,
            UserHandle = UserHandle,
            UserName = UserName,
            UserDisplayName = UserDisplayName,
            CredentialPublicKey = new CredentialPublicKey
            {
                KeyType = 2,
                Algorithm = -7,
                XCoordinate = [1, 2, 3, 4, 5, 6, 7, 8],
                YCoordinate = [9, 10, 11, 12, 13, 14, 15, 16],
            },
            SignCount = 0,
            Transports = ["usb", "nfc"],
        };
    }
}
