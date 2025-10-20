using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.3.4.1. ServerPublicKeyCredential.
/// </summary>
public sealed class ServerPublicKeyCredentialAttestation
{
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("rawId")]
    public required string RawId { get; init; }

    [JsonPropertyName("response")]
    public required ServerAuthenticatorAttestationResponse Response { get; init; }

    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("clientExtensionResults")]
    public ServerAuthenticationExtensionsClientOutputs? Extensions { get; init; }
}