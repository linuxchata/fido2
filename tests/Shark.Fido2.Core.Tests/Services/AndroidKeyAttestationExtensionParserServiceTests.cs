using Shark.Fido2.Core.Services;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Services;

[TestFixture]
public class AndroidKeyAttestationExtensionParserServiceTests
{
    private AndroidKeyAttestationExtensionParserService _sut;

    [SetUp]
    public void Setup()
    {
        _sut = new AndroidKeyAttestationExtensionParserService();
    }

    [Test]
    public void Parse_WhenValidData_ThenReturnsCorrectAttestation()
    {
        // Arrange
        var validAttestationData = ConvertHexStringToByteArray(
            "30-81-CF-02-01-02-0A-01-00-02-01-01-0A-01-00-04-20-9F-54-49-7C-DE-94-83-49-EA-E4-F4-8D-E9-70-80-8D-4D-DC-DC-E4-DD-EE-E2-3B-76-D5-C5-DD-CC-1B-89-8E-04-00-30-69-BF-85-3D-08-02-06-01-5E-D3-E3-CF-A0-BF-85-45-59-04-57-30-55-31-2F-30-2D-04-28-63-6F-6D-2E-61-6E-64-72-6F-69-64-2E-6B-65-79-73-74-6F-72-65-2E-61-6E-64-72-6F-69-64-6B-65-79-73-74-6F-72-65-64-65-6D-6F-02-01-01-31-22-04-20-74-CF-CB-50-74-88-F5-29-10-85-91-C7-A5-05-91-9F-32-77-32-FB-C1-D8-03-52-6A-EA-98-00-06-D2-D8-98-30-32-A1-05-31-03-02-01-02-A2-03-02-01-03-A3-04-02-02-01-00-A5-05-31-03-02-01-04-AA-03-02-01-01-BF-83-78-03-02-01-02-BF-85-3E-03-02-01-00-BF-85-3F-02-05-00");

        // Act
        var result = _sut.Parse(validAttestationData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.AttestationVersion, Is.EqualTo(2));
        Assert.That(result.AttestationSecurityLevel, Is.EqualTo(AndroidKeySecurityLevel.Software));
        Assert.That(result.KeymasterVersion, Is.EqualTo(1));
        Assert.That(result.KeymasterSecurityLevel, Is.EqualTo(AndroidKeySecurityLevel.Software));
        Assert.That(result.AttestationChallenge.Length, Is.EqualTo(32));
        Assert.That(result.UniqueId, Is.Empty);

        Assert.That(result.SoftwareEnforced, Is.Not.Null);
        Assert.That(result.SoftwareEnforced.Purpose, Is.Zero);
        Assert.That(result.SoftwareEnforced.IsAllApplicationsPresent, Is.False);
        Assert.That(result.SoftwareEnforced.Origin, Is.Zero);

        Assert.That(result.HardwareEnforced, Is.Not.Null);
        Assert.That(result.HardwareEnforced.Purpose, Is.EqualTo(2));
        Assert.That(result.HardwareEnforced.IsAllApplicationsPresent, Is.False);
        Assert.That(result.HardwareEnforced.Origin, Is.Zero);
    }

    [Test]
    public void Parse_WhenNullData_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.That(() => _sut.Parse(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Parse_WhenEmptyData_ThenReturnsNull()
    {
        // Arrange
        var emptyData = Array.Empty<byte>();

        // Act
        var result = _sut.Parse(emptyData);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void Parse_WhenInvalidData_ThenReturnsNull()
    {
        // Arrange
        var invalidData = new byte[] { 0x01, 0x02, 0x03 };

        // Act
        var result = _sut.Parse(invalidData);

        // Assert
        Assert.That(result, Is.Null);
    }

    private static byte[] ConvertHexStringToByteArray(string hex)
    {
        return hex.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray();
    }
}
