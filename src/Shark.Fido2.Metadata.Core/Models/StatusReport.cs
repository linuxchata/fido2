using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// An authenticator status and additional data associated with it, if any.
/// See: https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary.
/// </summary>
public sealed class StatusReport
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
