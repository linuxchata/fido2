using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// A relevant accuracy/complexity aspects of passcode user verification methods.
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#codeaccuracydescriptor-dictionary.
/// </summary>
public sealed class CodeAccuracyDescriptor
{
    [JsonPropertyName("base")]
    public ushort SystemBase { get; set; }

    [JsonPropertyName("minLength")]
    public ushort MinLength { get; set; }

    [JsonPropertyName("maxRetries")]
    public ushort? MaxRetries { get; set; }

    [JsonPropertyName("blockSlowdown")]
    public ushort? BlockSlowdown { get; set; }
}
