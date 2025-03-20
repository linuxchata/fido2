using System.Text.Json.Serialization;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// ECDAA-Issuer's trust anchor
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#ecdaatrustanchor-dictionary
/// </summary>
public sealed class EcdaaTrustAnchor
{
    [JsonPropertyName("X")]
    public required string X { get; set; }

    [JsonPropertyName("Y")]
    public required string Y { get; set; }

    [JsonPropertyName("c")]
    public required string C { get; set; }

    [JsonPropertyName("sx")]
    public required string Sx { get; set; }

    [JsonPropertyName("sy")]
    public required string Sy { get; set; }

    [JsonPropertyName("G1Curve")]
    public required string G1Curve { get; set; }
}
