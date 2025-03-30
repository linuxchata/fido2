using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// See: https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary.
/// </summary>
public sealed class BiometricStatusReport
{
    [JsonPropertyName("certLevel")]
    public ushort CertLevel { get; set; }

    [JsonPropertyName("modality")]
    public required string Modality { get; set; }

    [JsonPropertyName("effectiveDate")]
    public string? EffectiveDate { get; set; }

    [JsonPropertyName("certificationDescriptor")]
    public string? CertificationDescriptor { get; set; }

    [JsonPropertyName("certificateNumber")]
    public string? CertificateNumber { get; set; }

    [JsonPropertyName("certificationPolicyVersion")]
    public string? CertificationPolicyVersion { get; set; }

    [JsonPropertyName("certificationRequirementsVersion")]
    public string? CertificationRequirementsVersion { get; set; }
}
