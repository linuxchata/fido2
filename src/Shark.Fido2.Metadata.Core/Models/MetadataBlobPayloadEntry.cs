using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

public sealed class MetadataBlobPayloadEntry
{
    [JsonPropertyName("aaid")]
    public string? Aaid { get; set; }

    [JsonPropertyName("aaguid")]
    public Guid Aaguid { get; set; }

    [JsonPropertyName("attestationCertificateKeyIdentifiers")]
    public string[]? AttestationCertificateKeyIdentifiers { get; set; }

    [JsonPropertyName("metadataStatement")]
    public MetadataStatement? MetadataStatement { get; set; }

    [JsonPropertyName("biometricStatusReports")]
    public BiometricStatusReport[]? BiometricStatusReports { get; set; }

    [JsonPropertyName("statusReports")]
    public StatusReport[] StatusReports { get; set; } = [];

    [JsonPropertyName("timeOfLastStatusChange")]
    public string TimeOfLastStatusChange { get; set; } = string.Empty;

    [JsonPropertyName("rogueListURL")]
    public string? RogueListURL { get; set; }

    [JsonPropertyName("rogueListHash")]
    public string? RogueListHash { get; set; }

    public override string ToString()
    {
        return MetadataStatement?.Description ?? "-";
    }
}
