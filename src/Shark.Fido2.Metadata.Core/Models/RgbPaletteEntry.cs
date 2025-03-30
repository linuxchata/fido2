using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// A RGB three-sample tuple palette entry
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#rgbpaletteentry-dictionary.
/// </summary>
public sealed class RgbPaletteEntry
{
    [JsonPropertyName("r")]
    public byte Red { get; set; }

    [JsonPropertyName("g")]
    public byte Green { get; set; }

    [JsonPropertyName("b")]
    public byte Blue { get; set; }
}
