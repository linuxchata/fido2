using Shark.Fido2.Metadata.Core.Domain.Constants;

namespace Shark.Fido2.Metadata.Core.Domain;

/// <summary>
/// Represents metadata for an authenticator.
/// </summary>
public sealed class MetadataPayloadItem
{
    /// <summary>
    /// Gets the AAGUID of the authenticator.
    /// </summary>
    public Guid Aaguid { get; init; }

    /// <summary>
    /// Gets the human-readable description of the authenticator.
    /// </summary>
    public required string? Description { get; init; }

    /// <summary>
    /// Gets the status reports for the authenticator.
    /// </summary>
    public required StatusReport[] StatusReports { get; init; }

    /// <summary>
    /// Gets the attestation types supported by the authenticator.
    /// </summary>
    public required string[] AttestationTypes { get; init; }

    /// <summary>
    /// Gets a value indicating whether the authenticator has an increased risk status.
    /// </summary>
    /// <param name="now">The current date and time.</param>
    /// <returns><see langword="true"/> if the authenticator has an increased risk status; otherwise, <see langword="false"/>.</returns>
    public bool HasIncreasedRisk(DateTimeOffset now)
    {
        var lastStatusReport = GetLastStatusReport(now);
        if (lastStatusReport == null)
        {
            return false;
        }

        return AuthenticatorStatus.IncreasedRisk.Contains(lastStatusReport.Status);
    }

    /// <summary>
    /// Gets the last status of the authenticator.
    /// </summary>
    /// <param name="now">The current date and time.</param>
    /// <returns>The last status, or "-" if no status reports are present.</returns>
    public string GetLastStatus(DateTimeOffset now)
    {
        return GetLastStatusReport(now)?.Status ?? "-";
    }

    private StatusReport? GetLastStatusReport(DateTimeOffset now)
    {
        return StatusReports
            .Select((r, index) => (Report: r, Index: index, Date: r.ParseEffectiveDate()))
            .Where(x => x.Date is null || x.Date <= now)
            .OrderBy(x => x.Date ?? DateTimeOffset.MinValue)
            .ThenBy(x => x.Index)
            .Select(x => x.Report)
            .LastOrDefault();
    }
}
