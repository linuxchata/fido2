using Shark.Fido2.ConvenienceMetadata.Core.Constants;

namespace Shark.Fido2.ConvenienceMetadata.Core.Domain;

/// <summary>
/// Represents convenience metadata for an authenticator.
/// </summary>
public sealed class ConvenienceMetadataPayloadItem
{
    /// <summary>
    /// Gets the AAGUID of the authenticator.
    /// </summary>
    public Guid Aaguid { get; init; }

    /// <summary>
    /// Gets a human-readable friendly names of the authenticator.
    /// </summary>
    public Dictionary<string, string> FriendlyNames { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets a url encoded PNG or SVG light mode icon for the authenticator.
    /// </summary>
    public string? Icon { get; init; }

    /// <summary>
    /// Gets a url encoded SVG dark mode icon for the authenticator.
    /// </summary>
    public string? IconDark { get; init; }

    /// <summary>
    /// Gets a url encoded SVG light mode icon for the passkey provider.
    /// </summary>
    public string? ProviderLogoLight { get; init; }

    /// <summary>
    /// Gets a url encoded SVG dark mode icon for the passkey provider.
    /// </summary>
    public string? ProviderLogoDark { get; init; }

    /// <summary>
    /// Gets the default English (en-US) friendly name of the authenticator.
    /// </summary>
    /// <returns>The English friendly name, or <see langword="null"/> if not present.</returns>
    public string? GetDefaultName()
    {
        return FriendlyNames.GetValueOrDefault(Culture.EnglishUs);
    }
}
