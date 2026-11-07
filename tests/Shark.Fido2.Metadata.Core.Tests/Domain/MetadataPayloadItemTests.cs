using System.Globalization;
using Shark.Fido2.Metadata.Core.Domain;

namespace Shark.Fido2.Metadata.Core.Tests.Domain;

[TestFixture]
internal class MetadataPayloadItemTests
{
    private const string Description = nameof(Description);
    private const string FidoCertifiedStatus = "FIDO_CERTIFIED";
    private const string FidoNotCertifiedStatus = "NOT_FIDO_CERTIFIED";
    private const string UpdateAvailableStatus = "UPDATE_AVAILABLE";
    private const string RevokedStatus = "REVOKED";

    private readonly Guid _aaguid = Guid.NewGuid();
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);

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
        var result = item.HasIncreasedRisk(DateTimeOffset.Now);

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
        var result = item.HasIncreasedRisk(DateTimeOffset.Now);

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
        var result = item.HasIncreasedRisk(DateTimeOffset.Now);

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
        var result = item.HasIncreasedRisk(DateTimeOffset.Now);

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
        var result = item.GetLastStatus(DateTimeOffset.Now);

        // Assert
        Assert.That(result, Is.EqualTo("-"));
    }

    [Test]
    public void GetLastStatus_WhenSingleStatusReport_ThenReturnsStatus()
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
        var result = item.GetLastStatus(DateTimeOffset.Now);

        // Assert
        Assert.That(result, Is.EqualTo(FidoCertifiedStatus));
    }

    [Test]
    public void GetLastStatus_WhenMultipleStatusReports_ThenReturnsLatestStatus()
    {
        // Arrange
        var item = new MetadataPayloadItem
        {
            Aaguid = _aaguid,
            Description = Description,
            StatusReports =
            [
                new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
                new StatusReport { Status = UpdateAvailableStatus, EffectiveDate = "2023-02-01" },
                new StatusReport { Status = RevokedStatus, EffectiveDate = "2023-03-01" }
            ],
            AttestationTypes = [],
        };

        // Act
        var result = item.GetLastStatus(DateTimeOffset.Now);

        // Assert
        Assert.That(result, Is.EqualTo(RevokedStatus));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsAreNotInChronologicalOrder_ThenReturnsLatestStatus()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = RevokedStatus, EffectiveDate = "2023-03-01" },
            new StatusReport { Status = FidoNotCertifiedStatus, EffectiveDate = "2023-01-01" },
            new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-02-01" });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo(RevokedStatus));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsShareSameEffectiveDate_ThenReturnsLatestStatusInArrayOrder()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
            new StatusReport { Status = RevokedStatus, EffectiveDate = "2023-01-01" },
            new StatusReport { Status = FidoNotCertifiedStatus, EffectiveDate = "2023-01-01" });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo(FidoNotCertifiedStatus));
    }

    [Test]
    public void GetLastStatus_WhenLatestStatusReportIsInFuture_ThenReturnsPreviousStatus()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
            new StatusReport { Status = RevokedStatus, EffectiveDate = "2027-01-01" });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo(FidoCertifiedStatus));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsAreInFuture_ThenReturnsDash()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2027-01-01" },
            new StatusReport { Status = RevokedStatus, EffectiveDate = "2027-02-01" });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo("-"));
    }

    [Test]
    public void GetLastStatus_WhenOneStatusReportWithEffectiveDateEqualsNow_ThenReturnsLatestStatus()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
            new StatusReport { Status = RevokedStatus, EffectiveDate = "2026-11-01" });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo(RevokedStatus));
    }

    [TestCase("2023-06-01T12:00:00Z", "2023-06-01T11:59:59Z", FidoCertifiedStatus)]
    [TestCase("2023-06-01T12:00:00Z", "2023-06-01T12:00:00Z", RevokedStatus)]
    [TestCase("2023-06-01T12:00:00+02:00", "2023-06-01T09:59:59Z", FidoCertifiedStatus)]
    [TestCase("2023-06-01T12:00:00+02:00", "2023-06-01T10:00:00Z", RevokedStatus)]
    public void GetLastStatus_WhenOneStatusReportWithEffectiveDateWithTimeAndOffset_ThenReturnsCorrectStatus(
        string effectiveDate, string now, string expectedStatus)
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
            new StatusReport { Status = RevokedStatus, EffectiveDate = effectiveDate });

        // Act
        var result = item.GetLastStatus(ParseDate(now));

        // Assert
        Assert.That(result, Is.EqualTo(expectedStatus));
    }

    [Test]
    public void GetLastStatus_WhenSingleStatusReportWithoutEffectiveDate_ThenReturnsStatus()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = null });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo(FidoCertifiedStatus));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsWithoutEffectiveDate_ThenReturnsLatestStatusInArrayOrder()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = "A", EffectiveDate = null },
            new StatusReport { Status = "B", EffectiveDate = null },
            new StatusReport { Status = "C", EffectiveDate = null });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo("C"));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportWithoutEffectiveDateIsListedLast_ThenReturnsCorrectStatus()
    {
        // Arrange - a report with no date is treated as the oldest
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = "DATED", EffectiveDate = "2023-01-01" },
            new StatusReport { Status = "NO_DATE", EffectiveDate = null });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo("DATED"));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportWithoutEffectiveDateIsListedFirst_ThenReturnsCorrectStatus()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = "NO_DATE", EffectiveDate = null },
            new StatusReport { Status = "DATED", EffectiveDate = "2023-01-01" });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo("DATED"));
    }

    [Test]
    public void GetLastStatus_WhenOneStatusReportWithoutEffectiveDateAndOneStatusReportWithFutureEffectiveDate_ThenReturnsCorrectStatus()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = "NO_DATE", EffectiveDate = null },
            new StatusReport { Status = "FUTURE", EffectiveDate = "2030-01-01" });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo("NO_DATE"));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    [TestCase("not-a-date")]
    [TestCase("2023-13-45")]
    public void GetLastStatus_WhenOneStatusReportWithEffectiveDateMissingOrInvalid_ThenReturnsCorrectStatus(string? invalidDate)
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = "DATED", EffectiveDate = "2023-01-01" },
            new StatusReport { Status = "INVALID", EffectiveDate = invalidDate });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo("DATED"));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("not-a-date")]
    public void GetLastStatus_WhenOnlyStatusReportWithInvalidEffectiveDate_ThenReturnsCorrectStatus(string? invalidDate)
    {
        // Arrange
        var item = CreateMetadataPayloadItem(new StatusReport { Status = RevokedStatus, EffectiveDate = invalidDate });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo(RevokedStatus));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsWithMixOfUndatedPastAndFutureEffectiveDates_ThenReturnsCorrectStatus()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = "FUTURE", EffectiveDate = "2030-01-01" },
            new StatusReport { Status = "NO_DATE", EffectiveDate = null },
            new StatusReport { Status = "OLD", EffectiveDate = "2022-01-01" },
            new StatusReport { Status = "RECENT", EffectiveDate = "2023-05-01" },
            new StatusReport { Status = "INVALID", EffectiveDate = "baddata" });

        // Act
        var result = item.GetLastStatus(Now);

        // Assert
        Assert.That(result, Is.EqualTo("RECENT"));
    }

    [Test]
    public void GetLastStatus_WhenStatusReportsAndCalledWithDifferentNowValues_ThenReturnsCorrectStatus()
    {
        // Arrange
        var item = CreateMetadataPayloadItem(
            new StatusReport { Status = FidoCertifiedStatus, EffectiveDate = "2023-01-01" },
            new StatusReport { Status = RevokedStatus, EffectiveDate = "2023-03-01" },
            new StatusReport { Status = UpdateAvailableStatus, EffectiveDate = "2023-05-01" });

        // Act & Assert
        Assert.Multiple(() =>
        {
            Assert.That(item.GetLastStatus(ParseDate("2022-12-31")), Is.EqualTo("-"));
            Assert.That(item.GetLastStatus(ParseDate("2023-02-01")), Is.EqualTo(FidoCertifiedStatus));
            Assert.That(item.GetLastStatus(ParseDate("2023-04-01")), Is.EqualTo(RevokedStatus));
            Assert.That(item.GetLastStatus(ParseDate("2023-06-01")), Is.EqualTo(UpdateAvailableStatus));
        });
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

    private MetadataPayloadItem CreateMetadataPayloadItem(params StatusReport[] statusReports) => new()
    {
        Aaguid = _aaguid,
        Description = Description,
        StatusReports = statusReports,
        AttestationTypes = [],
    };

    private static DateTimeOffset ParseDate(string value)
    {
        return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
    }
}
