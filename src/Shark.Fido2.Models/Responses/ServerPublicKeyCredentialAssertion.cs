using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.3.4.1. ServerPublicKeyCredential
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential
/// </summary>
public sealed class ServerPublicKeyCredentialAssertion
{
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("rawId")]
    public required string RawId { get; init; }

    [JsonPropertyName("response")]
    public required ServerAuthenticatorAssertionResponse Response { get; init; }

    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("extensions")]
    public ServerAuthenticationExtensionsClientOutputs? Extensions { get; init; }
}