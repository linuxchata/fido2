using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Public key credential assertion.
/// </summary>
// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential.
public sealed class ServerPublicKeyCredentialAssertion
{
    /// <summary>
    /// Gets the credential's identifier. The value is base64url-encoded.
    /// </summary>
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>
    /// Gets the credential's raw identifier. The value is base64url-encoded.
    /// </summary>
    [JsonPropertyName("rawId")]
    public required string RawId { get; init; }

    /// <summary>
    /// Gets the authenticator assertion response.
    /// </summary>
    [JsonPropertyName("response")]
    public required ServerAuthenticatorAssertionResponse Response { get; init; }

    /// <summary>
    /// Gets the credential type.
    /// </summary>
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    /// <summary>
    /// Gets the client extension outputs.
    /// </summary>
    [JsonPropertyName("clientExtensionResults")]
    public ServerAuthenticationExtensionsClientOutputs? Extensions { get; init; }
}
