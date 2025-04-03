using Shark.Fido2.Metadata.Core.Domain.Constants;

namespace Shark.Fido2.Metadata.Core.Domain;

public sealed class MetadataPayloadItem
{
    public Guid Aaguid { get; init; }

    public required StatusReport[] StatusReports { get; init; }

    public required string[] AttestationTypes { get; init; }

    public bool HasIncreasedRisk()
    {
        var lastStatusReport = GetLastStatusReport();
        if (lastStatusReport == null)
        {
            return false;
        }

        return AuthenticatorStatus.IncreasedRisk.Contains(lastStatusReport.Status);
    }

    public string GetLastStatus()
    {
        return GetLastStatusReport()?.Status ?? "-";
    }

    private StatusReport? GetLastStatusReport()
    {
        return StatusReports.LastOrDefault();
    }
}
