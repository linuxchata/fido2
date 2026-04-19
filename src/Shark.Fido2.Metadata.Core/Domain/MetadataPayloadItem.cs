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
    /// <returns><see langword="true"/> if the authenticator has an increased risk status; otherwise, <see langword="false"/>.</returns>
    public bool HasIncreasedRisk()
    {
        var lastStatusReport = GetLastStatusReport();
        if (lastStatusReport == null)
        {
            return false;
        }

        return AuthenticatorStatus.IncreasedRisk.Contains(lastStatusReport.Status);
    }

    /// <summary>
    /// Gets the last status of the authenticator.
    /// </summary>
    /// <returns>The last status, or "-" if no status reports are present.</returns>
    public string GetLastStatus()
    {
        return GetLastStatusReport()?.Status ?? "-";
    }

    private StatusReport? GetLastStatusReport()
    {
        return StatusReports.LastOrDefault();
    }
}
