using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.3.4.1. ServerPublicKeyCredential
/// </summary>
public sealed class ServerPublicKeyCredentialAttestation
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = null!;

    [JsonPropertyName("rawId")]
    public string RawId { get; set; } = null!;

    [JsonPropertyName("response")]
    public ServerAuthenticatorAttestationResponse Response { get; set; } = null!;

    [JsonPropertyName("type")]
    public string Type { get; set; } = null!;

    [JsonPropertyName("extensions")]
    public ServerAuthenticationExtensionsClientOutputs Extensions { get; set; } = null!;
}