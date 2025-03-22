using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

public struct UnifiedProtocolVersion
{
    [JsonPropertyName("major")]
    public ushort Major { get; set; }

    [JsonPropertyName("minor")]
    public ushort Minor { get; set; }
}
