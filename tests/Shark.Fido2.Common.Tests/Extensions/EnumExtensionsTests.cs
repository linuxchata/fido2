using System.Runtime.Serialization;
using Shark.Fido2.Common.Extensions;

namespace Shark.Fido2.Common.Tests.Extensions;

public enum TestEnum
{
    [EnumMember(Value = "custom-value")]
    WithAttribute,
    WithoutAttribute,
}

[TestFixture]
internal class EnumExtensionsTests
{
    [Test]
    public void GetValue_WhenValueWithEnumMemberAttribute_ThenReturnsCustomValue()
    {
        // Arrange
        var value = TestEnum.WithAttribute;

        // Act
        var result = value.GetValue();

        // Assert
        Assert.That(result, Is.EqualTo("custom-value"));
    }

    [Test]
    public void GetValue_WhenValueWithoutEnumMemberAttribute_ThenReturnsEnumName()
    {
        // Arrange
        var value = TestEnum.WithoutAttribute;

        // Act
        var result = value.GetValue();

        // Assert
        Assert.That(result, Is.EqualTo("WithoutAttribute"));
    }

    [Test]
    public void ToEnum_WhenValueIsValid_ThenReturnsEnumItem()
    {
        // Arrange
        var value = "custom-value";

        // Act
        var result = value.ToEnum<TestEnum>();

        // Assert
        Assert.That(result, Is.EqualTo(TestEnum.WithAttribute));
    }

    [Test]
    public void ToEnum_WhenValueIsInvalid_ThenThrowsArgumentException()
    {
        // Arrange
        var value = "not-exist";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => value.ToEnum<TestEnum>());
    }

    [Test]
    public void ToNullableEnum_WhenValueIsNull_ThenReturnsNull()
    {
        // Arrange
        string? value = null;

        // Act
        var result = value.ToNullableEnum<TestEnum>();

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void ToNullableEnum_WhenValueIsValid_ThenReturnsEnumItem()
    {
        // Arrange
        string? value = "custom-value";

        // Act
        var result = value.ToNullableEnum<TestEnum>();

        // Assert
        Assert.That(result, Is.EqualTo(TestEnum.WithAttribute));
    }

    [Test]
    public void ToNullableEnum_WhenValueIsInvalid_ThenThrowsArgumentException()
    {
        // Arrange
        string? value = "not-exist";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => value.ToNullableEnum<TestEnum>());
    }
}
