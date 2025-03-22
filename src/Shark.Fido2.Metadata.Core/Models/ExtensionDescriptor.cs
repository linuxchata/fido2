using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// An extension supported by the authenticator
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary
/// </summary>
public sealed class ExtensionDescriptor
{
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    [JsonPropertyName("tag")]
    public ushort? Tag { get; set; }

    [JsonPropertyName("data")]
    public string? Data { get; set; }

    [JsonPropertyName("fail_if_unknown")]
    public required bool FailIfUnknown { get; set; }
}
