using System.Text;
using NUnit.Framework;
using Shark.Fido2.Common.Extensions;

namespace Shark.Fido2.Common.Tests.Extensions;

[TestFixture]
public class ConvertExtensionsTests
{
    [Test]
    public void ToBase64Url_ThenEncodesCorrectly()
    {
        // Arrange
        var bytes = Encoding.UTF8.GetBytes("hello world");

        // Act
        var result = bytes.ToBase64Url();

        // Assert
        Assert.That(result, Is.EqualTo("aGVsbG8gd29ybGQ"));
    }

    [Test]
    public void FromBase64Url_WhenBase64UrlIsValid_ThenDecodesValidBase64Url()
    {
        // Arrange
        var base64Url = "aGVsbG8gd29ybGQ";

        // Act
        var bytes = base64Url.FromBase64Url();
        var result = Encoding.UTF8.GetString(bytes);

        // Assert
        Assert.That(result, Is.EqualTo("hello world"));
    }

    [Test]
    public void FromBase64Url_WhenBase64UrlIsInvalid_ThenReturnsUtf8Bytes()
    {
        // Arrange
        var notBase64Url = "not_base64url";

        // Act
        var bytes = notBase64Url.FromBase64Url();
        var result = Encoding.UTF8.GetString(bytes);

        // Assert
        Assert.That(result, Is.EqualTo(notBase64Url));
    }

    [Test]
    public void IsBase64Url_WhenValid_ThenReturnsTrue()
    {
        // Arrange
        var base64Url = "aGVsbG8gd29ybGQ";

        // Act
        var result = base64Url.IsBase64Url();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsBase64Url_WhenInvalid_ThenReturnsFalse()
    {
        // Arrange
        var notBase64Url = "not_base64url";

        // Act
        var result = notBase64Url.IsBase64Url();

        // Assert
        Assert.That(result, Is.False);
    }
}
