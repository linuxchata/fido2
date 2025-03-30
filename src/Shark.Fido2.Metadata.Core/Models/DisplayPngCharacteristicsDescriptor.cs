using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// A PNG image characteristics as defined in the PNG [PNG] spec for IHDR (image header) and PLTE (palette table)
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary.
/// </summary>
public sealed class DisplayPngCharacteristicsDescriptor
{
    [JsonPropertyName("width")]
    public ulong Width { get; set; }

    [JsonPropertyName("height")]
    public ulong Height { get; set; }

    [JsonPropertyName("bitDepth")]
    public byte BitDepth { get; set; }

    [JsonPropertyName("colorType")]
    public byte ColorType { get; set; }

    [JsonPropertyName("compression")]
    public byte Compression { get; set; }

    [JsonPropertyName("filter")]
    public byte Filter { get; set; }

    [JsonPropertyName("interlace")]
    public byte Interlace { get; set; }

    [JsonPropertyName("plte")]
    public RgbPaletteEntry[]? Plte { get; set; }
}
