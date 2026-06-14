using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Public key credential descriptor.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor.
public sealed class ServerPublicKeyCredentialDescriptor
{
    /// <summary>
    /// Gets the credential type.
    /// </summary>
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    /// <summary>
    /// Gets the unique identifier of the credential, base64url-encoded.
    /// </summary>
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>
    /// Gets the communication transports supported/used by the authenticator.
    /// </summary>
    [JsonPropertyName("transports")]
    public required string[] Transports { get; init; }
}
