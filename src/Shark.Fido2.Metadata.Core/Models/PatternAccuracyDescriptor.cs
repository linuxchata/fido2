using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// The PatternAccuracyDescriptor describes relevant accuracy/complexity aspects in the case that a pattern
/// is used as the user verification method.
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary
/// </summary>
public sealed class PatternAccuracyDescriptor
{
    [JsonPropertyName("minComplexity")]
    public ulong MinComplexity { get; set; }

    [JsonPropertyName("maxRetries")]
    public ushort? MaxRetries { get; set; }

    [JsonPropertyName("blockSlowdown")]
    public ushort? BlockSlowdown { get; set; }
}
