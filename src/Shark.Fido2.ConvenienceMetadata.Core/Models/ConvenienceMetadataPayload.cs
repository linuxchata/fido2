using System.Text.Json;
using System.Text.Json.Serialization;

namespace Shark.Fido2.ConvenienceMetadata.Core.Models;

public sealed class ConvenienceMetadataPayload
{
    [JsonPropertyName("no")]
    public int No { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Entries { get; set; }
}
