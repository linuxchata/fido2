using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Entities;

public sealed class CredentialPublicKeyEntity
{
    [JsonPropertyName("kty")]
    public int KeyType { get; set; }

    [JsonPropertyName("alg")]
    public int Algorithm { get; set; }

    [JsonPropertyName("n")]
    public byte[]? Modulus { get; set; }

    [JsonPropertyName("e")]
    public byte[]? Exponent { get; set; }

    [JsonPropertyName("crv")]
    public int? Curve { get; set; }

    [JsonPropertyName("x")]
    public byte[]? XCoordinate { get; set; }

    [JsonPropertyName("y")]
    public byte[]? YCoordinate { get; set; }

    [JsonPropertyName("k")]
    public byte[]? Key { get; set; }
}
