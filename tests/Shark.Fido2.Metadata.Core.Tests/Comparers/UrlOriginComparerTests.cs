using Shark.Fido2.Metadata.Core.Comparers;

namespace Shark.Fido2.Metadata.Core.Tests.Comparers;

[TestFixture]
internal class UrlOriginComparerTests
{
    [Test]
    public void CompareOrigins_WhenBothUrlsAreNull_ThenReturnsFalse()
    {
        // Arrange
        string? left = null;
        string? right = null;

        // Act
        var result = UrlOriginComparer.CompareOrigins(left!, right!);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenLeftUrlIsNull_ThenReturnsFalse()
    {
        // Arrange
        string? left = null;
        var right = "https://example.com";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left!, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenRightUrlIsNull_ThenReturnsFalse()
    {
        // Arrange
        var left = "https://example.com";
        string? right = null;

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right!);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenBothUrlsAreInvalid_ThenReturnsFalse()
    {
        // Arrange
        var left = "invalid-url";
        var right = "also-invalid";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenLeftUrlIsInvalid_ThenReturnsFalse()
    {
        // Arrange
        var left = "invalid-url";
        var right = "https://example.com";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenRightUrlIsInvalid_ThenReturnsFalse()
    {
        // Arrange
        var left = "https://example.com";
        var right = "invalid-url";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenBothUrlsAreIdentical_ThenReturnsTrue()
    {
        // Arrange
        var left = "https://example.com";
        var right = "https://example.com";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareOrigins_WhenBothUrlsHaveSameSchemeAndHost_ThenReturnsTrue()
    {
        // Arrange
        var left = "https://example.com/path1";
        var right = "https://example.com/path2";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareOrigins_WhenUrlsHaveDifferentSchemes_ThenReturnsFalse()
    {
        // Arrange
        var left = "https://example.com";
        var right = "http://example.com";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenUrlsHaveDifferentHosts_ThenReturnsFalse()
    {
        // Arrange
        var left = "https://example.com";
        var right = "https://different.com";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenUrlsHaveDifferentPorts_ThenReturnsFalse()
    {
        // Arrange
        var left = "https://example.com:8080";
        var right = "https://example.com:9090";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenUrlsHaveSamePortExplicitly_ThenReturnsTrue()
    {
        // Arrange
        var left = "https://example.com:443";
        var right = "https://example.com:443";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareOrigins_WhenOneUrlHasDefaultPortAndOtherDoesNot_ThenReturnsFalse()
    {
        // Arrange
        var left = "https://example.com";
        var right = "https://example.com:443";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenUrlsHaveDifferentQueryStrings_ThenReturnsTrue()
    {
        // Arrange
        var left = "https://example.com?param1=value1";
        var right = "https://example.com?param2=value2";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareOrigins_WhenUrlsHaveSubdomains_ThenReturnsFalse()
    {
        // Arrange
        var left = "https://sub1.example.com";
        var right = "https://sub2.example.com";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareOrigins_WhenUrlsHaveDifferentCasing_ThenReturnsTrue()
    {
        // Arrange
        var left = "https://EXAMPLE.COM";
        var right = "https://example.com";

        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.True);
    }

    [TestCase("ftp://example.com", "ftp://example.com", true)]
    [TestCase("file:///path/to/file", "file:///different/path", true)]
    [TestCase("ws://example.com", "ws://example.com", true)]
    [TestCase("wss://example.com", "wss://example.com", true)]
    public void CompareOrigins_WhenUsingDifferentSchemes_ThenReturnsExpectedResult(string left, string right, bool expected)
    {
        // Act
        var result = UrlOriginComparer.CompareOrigins(left, right);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }
}