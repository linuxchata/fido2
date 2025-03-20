using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// The BiometricAccuracyDescriptor describes relevant accuracy/complexity aspects in the case of a biometric
/// user verification method
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary
/// </summary>
public sealed class BiometricAccuracyDescriptor
{
    [JsonPropertyName("selfAttestedFrr")]
    public double? SelfAttestedFRR { get; set; }

    [JsonPropertyName("selfAttestedFar")]
    public double? SelfAttestedFAR { get; set; }

    [JsonPropertyName("maxTemplates")]
    public ushort? MaxTemplates { get; set; }

    [JsonPropertyName("maxRetries")]
    public ushort? MaxRetries { get; set; }

    [JsonPropertyName("blockSlowdown")]
    public ushort? BlockSlowdown { get; set; }
}
