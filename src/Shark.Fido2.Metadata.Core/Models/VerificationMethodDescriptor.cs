using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// A descriptor for a specific base user verification method as implemented by the authenticator.
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary
/// </summary>
public sealed class VerificationMethodDescriptor
{
    [JsonPropertyName("userVerificationMethod")]
    public string? UserVerificationMethod { get; set; }

    [JsonPropertyName("caDesc")]
    public CodeAccuracyDescriptor? CaDesc { get; set; }

    [JsonPropertyName("baDesc")]
    public BiometricAccuracyDescriptor? BaDesc { get; set; }

    [JsonPropertyName("paDesc")]
    public PatternAccuracyDescriptor? PaDesc { get; set; }
}
