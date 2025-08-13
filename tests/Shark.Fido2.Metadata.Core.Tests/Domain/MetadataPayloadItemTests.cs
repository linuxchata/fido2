using Shark.Fido2.Metadata.Core.Domain;

namespace Shark.Fido2.Metadata.Core.Tests.Domain;

[TestFixture]
internal class MetadataPayloadItemTests
{
    private const string Description = nameof(Description);
    private const string FidoCertifiedStatus = "FIDO_CERTIFIED";
    private const string RevokedStatus = "REVOKED";

    private readonly Guid _aaguid = Guid.NewGuid();

    [Test]
    public void HasIncreasedRisk_WhenStatusReportsIsEmpty_ThenReturnsFalse()
    {
        // Arrange
        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports = [],
            AttestationTypes = [],
        };

        // Act
        var result = item.HasIncreasedRisk();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void HasIncreasedRisk_WhenLastStatusIsNotIncreasedRisk_ThenReturnsFalse()
    {
        // Arrange
        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" }
            ],
            AttestationTypes = [],
        };

        // Act
        var result = item.HasIncreasedRisk();

        // Assert
        Assert.That(result, Is.False);
    }

    [TestCase("USER_VERIFICATION_BYPASS")]
    [TestCase("ATTESTATION_KEY_COMPROMISE")]
    [TestCase("USER_KEY_REMOTE_COMPROMISE")]
    [TestCase("USER_KEY_PHYSICAL_COMPROMISE")]
    [TestCase("REVOKED")]
    public void HasIncreasedRisk_WhenLastStatusIsIncreasedRisk_ThenReturnsTrue(string riskStatus)
    {
        // Arrange
        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
                new StatusReport { Status = riskStatus, EffectiveDate = "2023-02-01" }
            ],
            AttestationTypes = [],
        };

        // Act
        var result = item.HasIncreasedRisk();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void HasIncreasedRisk_WhenMultipleStatusReportsWithLastOneNotRisky_ThenReturnsFalse()
    {
        // Arrange
        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
                new StatusReport { Status = RevokedStatus, EffectiveDate = "2023-02-01" },
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-03-01" }
            ],
            AttestationTypes = [],
        };

        // Act
        var result = item.HasIncreasedRisk();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsIsEmpty_ThenReturnsDash()
    {
        // Arrange
        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports = [],
            AttestationTypes = [],
        };

        // Act
        var result = item.GetLastStatus();

        // Assert
        Assert.That(result, Is.EqualTo("-"));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsHasOneItem_ThenReturnsStatus()
    {
        // Arrange
        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" }
            ],
            AttestationTypes = [],
        };

        // Act
        var result = item.GetLastStatus();

        // Assert
        Assert.That(result, Is.EqualTo(FidoCertifiedStatus));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsHasMultipleItems_ThenReturnsLastStatus()
    {
        // Arrange
        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
                new StatusReport { Status = "UPDATE_AVAILABLE", EffectiveDate = "2023-02-01" },
                new StatusReport { Status = RevokedStatus, EffectiveDate = "2023-03-01" }
            ],
            AttestationTypes = [],
        };

        // Act
        var result = item.GetLastStatus();

        // Assert
        Assert.That(result, Is.EqualTo(RevokedStatus));
    }

    [Test]
    public void Properties_WhenInitialized_ThenReturnExpectedValues()
    {
        // Arrange
        var statusReports = new StatusReport[]
        {
            new() { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
        };
        var attestationTypes = new string[] { "basic", "self" };

        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports = statusReports,
            AttestationTypes = attestationTypes,
        };

        // Act & Assert
        Assert.That(item.Aaguid, Is.EqualTo(_aaguid));
        Assert.That(item.Description, Is.EqualTo(Description));
        Assert.That(item.StatusReports, Is.EqualTo(statusReports));
        Assert.That(item.AttestationTypes, Is.EqualTo(attestationTypes));
    }
}