using System.Security.Cryptography;
using System.Text;
using Shark.Fido2.Core.Helpers;

namespace Shark.Fido2.Core.Tests.Helpers;

[TestFixture]
public class HashProviderTests
{
    private const string TestString = "test data";

    private static readonly byte[] TestData = Encoding.UTF8.GetBytes("test data");

    [Test]
    public void GetHash_WhenWithSHA1_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA1.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA1);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WhenWithSHA256_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WhenWithSHA384_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA384.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA384);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WhenWithSHA512_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA512.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA512);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WhenWithNullValue_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetHash(null!, HashAlgorithmName.SHA256));
    }

    [Test]
    public void GetHash_WhenWithUnsupportedAlgorithm_ThenThrowsNotSupportedException()
    {
        // Act & Assert
        Assert.Throws<NotSupportedException>(() => HashProvider.GetHash(TestData, new HashAlgorithmName("MD5")));
    }

    [Test]
    public void GetSha256Hash_WhenWithValidString_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes(TestString));

        // Act
        var result = HashProvider.GetSha256Hash(TestString);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetSha256Hash_WhenWithNullString_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash((string)null!));
    }

    [Test]
    public void GetSha256Hash_WhenWithEmptyString_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash(string.Empty));
    }

    [Test]
    public void GetSha256Hash_WhenWithWhiteSpaceString_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash("   "));
    }

    [Test]
    public void GetSha256Hash_WhenWithByteArray_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(TestData);

        // Act
        var result = HashProvider.GetSha256Hash(TestData);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetSha256Hash_WhenWithNullByteArray_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash((byte[])null!));
    }
}
