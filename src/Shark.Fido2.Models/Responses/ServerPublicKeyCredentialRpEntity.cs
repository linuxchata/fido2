using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Public key credential Relying Party entity.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrpentity.
public sealed class ServerPublicKeyCredentialRpEntity
{
    /// <summary>
    /// Gets the Relying Party identifier.
    /// </summary>
    [JsonPropertyName("id")]
    public required string Identifier { get; init; }

    /// <summary>
    /// Gets the friendly/display name of the Relying Party.
    /// </summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }
}
