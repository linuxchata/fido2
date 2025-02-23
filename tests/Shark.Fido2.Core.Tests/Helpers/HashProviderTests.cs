using System.Security.Cryptography;
using System.Text;
using Shark.Fido2.Core.Helpers;

namespace Shark.Fido2.Core.Tests.Helpers;

[TestFixture]
public class HashProviderTests
{
    private static readonly byte[] TestData = Encoding.UTF8.GetBytes("test data");
    private const string TestString = "test data";

    [Test]
    public void GetHash_WithSHA1_ReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA1.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA1);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WithSHA256_ReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WithSHA384_ReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA384.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA384);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WithSHA512_ReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA512.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA512);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WithNullValue_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetHash(null!, HashAlgorithmName.SHA256));
    }

    [Test]
    public void GetHash_WithUnsupportedAlgorithm_ThrowsNotSupportedException()
    {
        // Act & Assert
        Assert.Throws<NotSupportedException>(() => HashProvider.GetHash(TestData, new HashAlgorithmName("MD5")));
    }

    [Test]
    public void GetSha256Hash_WithValidString_ReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes(TestString));

        // Act
        var result = HashProvider.GetSha256Hash(TestString);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetSha256Hash_WithNullString_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash((string)null!));
    }

    [Test]
    public void GetSha256Hash_WithEmptyString_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash(string.Empty));
    }

    [Test]
    public void GetSha256Hash_WithWhiteSpaceString_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash("   "));
    }

    [Test]
    public void GetSha256Hash_WithByteArray_ReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(TestData);

        // Act
        var result = HashProvider.GetSha256Hash(TestData);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetSha256Hash_WithNullByteArray_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash((byte[])null!));
    }
}
