using System.Globalization;

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

    public DateTimeOffset? ParseEffectiveDate()
    {
        // Case: effective while present - if there's no date, the status
        // counts as active for as long as the entry is in the list.
        if (string.IsNullOrWhiteSpace(EffectiveDate))
        {
            return null;
        }

        return DateTimeOffset.TryParse(
            EffectiveDate,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal,
            out var result)
            ? result
            : DateTimeOffset.MaxValue;
    }
}
