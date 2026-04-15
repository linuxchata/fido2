using System.Text.Json.Serialization;

namespace Shark.Fido2.ConvenienceMetadata.Core.Models;

public sealed class ConvenienceDetails
{
    [JsonPropertyName("friendlyNames")]
    public Dictionary<string, string> FriendlyNames { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    [JsonPropertyName("icon")]
    public string? Icon { get; set; }

    [JsonPropertyName("iconDark")]
    public string? IconDark { get; set; }

    [JsonPropertyName("providerLogoLight")]
    public string? ProviderLogoLight { get; set; }

    [JsonPropertyName("providerLogoDark")]
    public string? ProviderLogoDark { get; set; }
}
