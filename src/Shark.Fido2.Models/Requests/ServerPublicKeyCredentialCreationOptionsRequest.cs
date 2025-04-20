using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Requests;

/// <summary>
/// 7.3.3.1. ServerPublicKeyCredentialCreationOptionsRequest
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsrequest.
/// </summary>
public sealed class ServerPublicKeyCredentialCreationOptionsRequest
{
    [JsonPropertyName("username")]
    [JsonRequired]
    public required string Username { get; init; }

    [JsonPropertyName("displayName")]
    [JsonRequired]
    public required string DisplayName { get; init; }

    [JsonPropertyName("authenticatorSelection")]
    public ServerAuthenticatorSelectionCriteriaRequest? AuthenticatorSelection { get; init; }

    [JsonPropertyName("attestation")]
    public string? Attestation { get; init; }
}