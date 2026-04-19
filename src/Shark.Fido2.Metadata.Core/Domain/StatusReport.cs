namespace Shark.Fido2.Metadata.Core.Domain;

/// <summary>
/// Represents a status report for an authenticator.
/// </summary>
public sealed class StatusReport
{
    /// <summary>
    /// Gets the date when the status became effective.
    /// </summary>
    public string? EffectiveDate { get; init; }

    /// <summary>
    /// Gets the status of the authenticator.
    /// </summary>
    public required string Status { get; init; }
}
