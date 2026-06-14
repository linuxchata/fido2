using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Public key credential attestation.
/// </summary>
public sealed class ServerPublicKeyCredentialAttestation
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
    /// Gets the authenticator attestation response.
    /// </summary>
    [JsonPropertyName("response")]
    public required ServerAuthenticatorAttestationResponse Response { get; init; }

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
