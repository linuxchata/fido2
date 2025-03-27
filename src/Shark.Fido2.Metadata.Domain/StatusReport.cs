namespace Shark.Fido2.Metadata.Domain;

public sealed class StatusReport
{
    public string? EffectiveDate { get; init; }

    public required string Status { get; init; }
}
