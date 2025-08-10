using Shark.Fido2.Core.Dictionaries;

namespace Shark.Fido2.Core.Tests.Dictionaries;

[TestFixture]
internal class TpmCapabilitiesVendorsTests
{
    [Test]
    public void Exists_WhenVerdonIdIsNull_ThenReturnsFalse()
    {
        // Arrange
        string? vendorId = null;

        // Act
        var result = TpmCapabilitiesVendors.Exists(vendorId);

        // Assert
        Assert.That(result, Is.False);
    }

    [TestCase("")]
    [TestCase("   ")]
    public void Exists_WhenVerdonIdIsEmpty_ThenReturnsFalse(string vendorId)
    {
        // Act
        var result = TpmCapabilitiesVendors.Exists(vendorId);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void Exists_WhenVerdonIdDoesNotExist_ThenReturnsFalse()
    {
        // Arrange
        string vendorId = "12345d00";

        // Act
        var result = TpmCapabilitiesVendors.Exists(vendorId);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void Exists_WhenVendorIdHasExtraSpace_ThenReturnsFalse()
    {
        // Arrange
        string vendorId = " 414D4400 ";

        // Act
        var result = TpmCapabilitiesVendors.Exists(vendorId);

        // Assert
        Assert.That(result, Is.False);
    }

    [TestCase("4353434F")]
    [TestCase("414D4400")]
    [TestCase("49424D00")]
    [TestCase("49424d00")]
    public void Exists_WhenVerdonIdIsMatched_ThenReturnsTrue(string vendorId)
    {
        // Act
        var result = TpmCapabilitiesVendors.Exists(vendorId);

        // Assert
        Assert.That(result, Is.True);
    }
}