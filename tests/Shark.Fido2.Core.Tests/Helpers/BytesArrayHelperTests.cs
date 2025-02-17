using Shark.Fido2.Core.Helpers;

namespace Shark.Fido2.Core.Tests.Helpers;

[TestFixture]
public class BytesArrayHelperTests
{
    [Test]
    public void Concatenate_BothArraysNull_ReturnsEmptyArray()
    {
        // Act
        var result = BytesArrayHelper.Concatenate(null, null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void Concatenate_LeftArrayNull_ReturnsRightArrayCopy()
    {
        // Arrange
        var right = new byte[] { 1, 2, 3 };

        // Act
        var result = BytesArrayHelper.Concatenate(null, right);

        // Assert
        Assert.That(result, Is.EqualTo(right));
        Assert.That(result, Is.Not.SameAs(right));
    }

    [Test]
    public void Concatenate_RightArrayNull_ReturnsLeftArrayCopy()
    {
        // Arrange
        var left = new byte[] { 1, 2, 3 };

        // Act
        var result = BytesArrayHelper.Concatenate(left, null);

        // Assert
        Assert.That(result, Is.EqualTo(left));
        Assert.That(result, Is.Not.SameAs(left));
    }

    [Test]
    public void Concatenate_BothArraysNonNull_ReturnsConcatenatedArray()
    {
        // Arrange
        var left = new byte[] { 1, 2, 3 };
        var right = new byte[] { 4, 5, 6 };
        var expected = new byte[] { 1, 2, 3, 4, 5, 6 };

        // Act
        var result = BytesArrayHelper.Concatenate(left, right);

        // Assert
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void Concatenate_WithEmptyArray_ReturnsCopyOfNonEmptyArray()
    {
        // Arrange
        var nonEmpty = new byte[] { 1, 2, 3 };
        var empty = Array.Empty<byte>();

        // Act
        var resultLeft = BytesArrayHelper.Concatenate(empty, nonEmpty);
        var resultRight = BytesArrayHelper.Concatenate(nonEmpty, empty);

        // Assert
        Assert.That(resultLeft, Is.EqualTo(nonEmpty));
        Assert.That(resultRight, Is.EqualTo(nonEmpty));
        Assert.That(resultLeft, Is.Not.SameAs(nonEmpty));
        Assert.That(resultRight, Is.Not.SameAs(nonEmpty));
    }
}
