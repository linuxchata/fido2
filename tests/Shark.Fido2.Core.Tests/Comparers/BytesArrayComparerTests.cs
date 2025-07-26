using Shark.Fido2.Core.Comparers;

namespace Shark.Fido2.Core.Tests.Comparers;

[TestFixture]
internal class BytesArrayComparerTests
{
    [Test]
    public void CompareNullable_WhenBothNull_ThenReturnsTrue()
    {
        // Arrange
        byte[]? expected = null;
        byte[]? actual = null;

        // Act
        var result = BytesArrayComparer.CompareNullable(expected, actual);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareNullable_WhenExpectedNull_ThenReturnsFalse()
    {
        // Arrange
        byte[]? expected = null;
        byte[] actual = [1, 2, 3];

        // Act
        var result = BytesArrayComparer.CompareNullable(expected, actual);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareNullable_WhenActualNull_ThenReturnsFalse()
    {
        // Arrange
        byte[] expected = [1, 2, 3];
        byte[]? actual = null;

        // Act
        var result = BytesArrayComparer.CompareNullable(expected, actual);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareNullable_WhenSameReference_ThenReturnsTrue()
    {
        // Arrange
        byte[] expected = [1, 2, 3];
        byte[] actual = expected;

        // Act
        var result = BytesArrayComparer.CompareNullable(expected, actual);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareNullable_WhenDifferentLengths_ThenReturnsFalse()
    {
        // Arrange
        byte[] expected = [1, 2, 3];
        byte[] actual = [1, 2];

        // Act
        var result = BytesArrayComparer.CompareNullable(expected, actual);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareNullable_WhenSameContent_ThenReturnsTrue()
    {
        // Arrange
        byte[] expected = [1, 2, 3];
        byte[] actual = [1, 2, 3];

        // Act
        var result = BytesArrayComparer.CompareNullable(expected, actual);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareNullable_WhenDifferentContent_ThenReturnsFalse()
    {
        // Arrange
        byte[] expected = [1, 2, 3];
        byte[] actual = [1, 2, 4];

        // Act
        var result = BytesArrayComparer.CompareNullable(expected, actual);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void CompareAsSpan_WhenEmpty_ThenReturnsTrue()
    {
        // Arrange
        ReadOnlySpan<byte> expected = [];
        ReadOnlySpan<byte> actual = [];

        // Act
        var result = BytesArrayComparer.CompareAsSpan(expected, actual);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareAsSpan_WhenSameContent_ThenReturnsTrue()
    {
        // Arrange
        ReadOnlySpan<byte> expected = new byte[] { 1, 2, 3 };
        ReadOnlySpan<byte> actual = new byte[] { 1, 2, 3 };

        // Act
        var result = BytesArrayComparer.CompareAsSpan(expected, actual);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void CompareAsSpan_WhenDifferentContent_ThenReturnsFalse()
    {
        // Arrange
        ReadOnlySpan<byte> expected = new byte[] { 1, 2, 3 };
        ReadOnlySpan<byte> actual = new byte[] { 1, 2, 4 };

        // Act
        var result = BytesArrayComparer.CompareAsSpan(expected, actual);

        // Assert
        Assert.That(result, Is.False);
    }
}