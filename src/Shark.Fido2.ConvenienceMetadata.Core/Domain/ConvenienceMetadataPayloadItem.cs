namespace Shark.Fido2.ConvenienceMetadata.Core.Domain;

public sealed class ConvenienceMetadataPayloadItem
{
    public Guid Aaguid { get; init; }

    public Dictionary<string, string> FriendlyNames { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public string? Icon { get; init; }

    public string? IconDark { get; init; }

    public string? ProviderLogoLight { get; init; }

    public string? ProviderLogoDark { get; init; }
}
