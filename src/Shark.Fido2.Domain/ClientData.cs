using System.Text.Json.Serialization;

namespace Shark.Fido2.Domain;

/// <summary>
/// 5.8.1. Client Data Used in WebAuthn Signatures
/// https://www.w3.org/TR/webauthn-2/#dictionary-client-data.
/// </summary>
public sealed class ClientData
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    [JsonPropertyName("origin")]
    public required string Origin { get; init; }

    [JsonPropertyName("crossOrigin")]
    public bool CrossOrigin { get; init; }

    [JsonPropertyName("tokenBinding")]
    public TokenBinding? TokenBinding { get; init; }

    [JsonIgnore]
    public byte[]? ClientDataHash { get; set; }
}
