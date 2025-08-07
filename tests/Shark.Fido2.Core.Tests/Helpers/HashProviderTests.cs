using System.Security.Cryptography;
using System.Text;
using Shark.Fido2.Core.Helpers;

namespace Shark.Fido2.Core.Tests.Helpers;

[TestFixture]
internal class HashProviderTests
{
    private const string TestString = "test data";

    private static readonly byte[] TestData = Encoding.UTF8.GetBytes("test data");

    [Test]
    public void GetHash_WhenHashAlgorithmNameIsSHA1_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA1.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA1);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WhenHashAlgorithmNameIsSHA256_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WhenHashAlgorithmNameIsSHA384_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA384.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA384);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WhenHashAlgorithmNameIsSHA512_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA512.HashData(TestData);

        // Act
        var result = HashProvider.GetHash(TestData, HashAlgorithmName.SHA512);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetHash_WhenHashAlgorithmNameIsUnsupported_ThenThrowsNotSupportedException()
    {
        // Act & Assert
        Assert.Throws<NotSupportedException>(() => HashProvider.GetHash(TestData, new HashAlgorithmName("MD5")));
    }

    [Test]
    public void GetHash_WhenValueIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetHash(null!, HashAlgorithmName.SHA256));
    }

    [Test]
    public void GetSha256Hash_WhenValueIsValidString_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes(TestString));

        // Act
        var result = HashProvider.GetSha256Hash(TestString);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void GetSha256Hash_WhenValueIsNullOrEmpty_ThenThrowsArgumentNullException(string? value)
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash(value!));
    }

    [Test]
    public void GetSha256Hash_WhenValueIsByteArray_ThenReturnsCorrectHash()
    {
        // Arrange
        var expected = SHA256.HashData(TestData);

        // Act
        var result = HashProvider.GetSha256Hash(TestData);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void GetSha256Hash_WhenValueIsNullByteArray_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => HashProvider.GetSha256Hash((byte[])null!));
    }
}
