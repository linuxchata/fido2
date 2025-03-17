using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

public class StatusReport
{
    [JsonPropertyName("status")]
    public required string Status { get; set; }

    [JsonPropertyName("effectiveDate")]
    public string? EffectiveDate { get; set; }

    [JsonPropertyName("authenticatorVersion")]
    public ulong AuthenticatorVersion { get; set; }

    [JsonPropertyName("certificate")]
    public string? Certificate { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("certificationDescriptor")]
    public string? CertificationDescriptor { get; set; }

    [JsonPropertyName("certificateNumber")]
    public string? CertificateNumber { get; set; }

    [JsonPropertyName("certificationPolicyVersion")]
    public string? CertificationPolicyVersion { get; set; }

    [JsonPropertyName("certificationRequirementsVersion")]
    public string? CertificationRequirementsVersion { get; set; }
}
