using Shark.Fido2.Core.Helpers;

namespace Shark.Fido2.Core.Tests.Helpers;

[TestFixture]
public class BytesArrayHelperTests
{
    #region Concatenate Tests

    [Test]
    public void Concatenate_WhenBothArraysAreNull_ReturnsEmptyArray()
    {
        // Act
        var result = BytesArrayHelper.Concatenate(null, null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void Concatenate_WhenLeftArrayIsNull_ReturnsRightArrayCopy()
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
    public void Concatenate_WhenRightArrayIsNull_ReturnsLeftArrayCopy()
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
    public void Concatenate_WhenBothArraysAreNonNull_ReturnsConcatenatedArray()
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
    public void Concatenate_WhenRightArrayIsEmpty_ReturnsCopyOfLeftArray()
    {
        // Arrange
        var left = new byte[] { 1, 2, 3 };
        var right = Array.Empty<byte>();

        // Act
        var resultLeft = BytesArrayHelper.Concatenate(right, left);
        var resultRight = BytesArrayHelper.Concatenate(left, right);

        // Assert
        Assert.That(resultLeft, Is.EqualTo(left));
        Assert.That(resultRight, Is.EqualTo(left));
        Assert.That(resultLeft, Is.Not.SameAs(left));
        Assert.That(resultRight, Is.Not.SameAs(left));
    }

    #endregion

    #region Split Tests

    [Test]
    public void Split_WhenArrayIsNull_ReturnsTwoEmptyArrays()
    {
        // Act
        var (left, right) = BytesArrayHelper.Split(null);

        // Assert
        Assert.That(left, Is.Not.Null);
        Assert.That(right, Is.Not.Null);
        Assert.That(left, Is.Empty);
        Assert.That(right, Is.Empty);
    }

    [Test]
    public void Split_WhenArrayIsEmpty_ReturnsTwoEmptyArrays()
    {
        // Arrange
        var array = Array.Empty<byte>();

        // Act
        var (left, right) = BytesArrayHelper.Split(array);

        // Assert
        Assert.That(left, Is.Not.Null);
        Assert.That(right, Is.Not.Null);
        Assert.That(left, Is.Empty);
        Assert.That(right, Is.Empty);
    }

    [Test]
    public void Split_WhenArrayHasOddLength_ReturnsTwoEmptyArrays()
    {
        // Arrange
        var array = new byte[] { 1, 2, 3 };

        // Act
        var (left, right) = BytesArrayHelper.Split(array);

        // Assert
        Assert.That(left, Is.Not.Null);
        Assert.That(right, Is.Not.Null);
        Assert.That(left, Is.Empty);
        Assert.That(right, Is.Empty);
    }

    [Test]
    public void Split_WhenArrayHasEventLength_ReturnsTwoEqualParts()
    {
        // Arrange
        var array = new byte[] { 1, 2, 3, 4 };
        var expectedLeft = new byte[] { 1, 2 };
        var expectedRight = new byte[] { 3, 4 };

        // Act
        var (left, right) = BytesArrayHelper.Split(array);

        // Assert
        Assert.That(left, Is.EqualTo(expectedLeft));
        Assert.That(right, Is.EqualTo(expectedRight));
    }

    [Test]
    public void Split_WhenLargerArrayHasEventLength_ReturnsTwoEqualParts()
    {
        // Arrange
        var array = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var expectedLeft = new byte[] { 1, 2, 3, 4 };
        var expectedRight = new byte[] { 5, 6, 7, 8 };

        // Act
        var (left, right) = BytesArrayHelper.Split(array);

        // Assert
        Assert.That(left, Is.EqualTo(expectedLeft));
        Assert.That(right, Is.EqualTo(expectedRight));
    }

    #endregion
}
