using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

public sealed class MetadataStatement
{
    [JsonPropertyName("legalHeader")]
    public string? LegalHeader { get; set; }

    [JsonPropertyName("aaid")]
    public string? Aaid { get; set; }

    [JsonPropertyName("aaguid")]
    public Guid Aaguid { get; set; }

    [JsonPropertyName("description")]
    public required string Description { get; set; }

    [JsonPropertyName("authenticatorVersion")]
    public required ulong AuthenticatorVersion { get; set; }

    public override string ToString()
    {
        return Description;
    }
}
