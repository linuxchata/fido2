using System.Text.Json.Serialization;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain;

/// <summary>
/// 5.8.1. Client Data Used in WebAuthn Signatures
/// https://www.w3.org/TR/webauthn-2/#dictionary-client-data.
/// </summary>
public sealed class TokenBinding
{
    [JsonPropertyName("status")]
    [JsonConverter(typeof(TokenBindingStatusConverter))]
    public TokenBindingStatus Status { get; set; }

    [JsonPropertyName("id")]
    public string? Id { get; set; }
}
