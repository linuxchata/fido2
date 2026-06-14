using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Requests;

/// <summary>
/// Public key credential creation options request.
/// </summary>
// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsrequest.
public sealed class ServerPublicKeyCredentialCreationOptionsRequest
{
    /// <summary>
    /// Gets the user's username.
    /// </summary>
    [JsonPropertyName("username")]
    [JsonRequired]
    public required string Username { get; init; }

    /// <summary>
    /// Gets the user's friendly/display name.
    /// </summary>
    [JsonPropertyName("displayName")]
    [JsonRequired]
    public required string DisplayName { get; init; }

    /// <summary>
    /// Gets the criteria to guide the authenticator selection.
    /// </summary>
    [JsonPropertyName("authenticatorSelection")]
    public ServerAuthenticatorSelectionCriteriaRequest? AuthenticatorSelection { get; init; }

    /// <summary>
    /// Gets the preferred attestation conveyance preference.
    /// </summary>
    [JsonPropertyName("attestation")]
    public string? Attestation { get; init; }
}
