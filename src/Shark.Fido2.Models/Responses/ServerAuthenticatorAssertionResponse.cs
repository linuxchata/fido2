using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Authenticator assertion response.
/// </summary>
// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverauthenticatorassertionresponse.
public sealed class ServerAuthenticatorAssertionResponse : ServerAuthenticatorResponse
{
    /// <summary>
    /// Gets the base64url-encoded JSON-serialized client data.
    /// </summary>
    [JsonPropertyName("clientDataJSON")]
    public required string ClientDataJson { get; init; }

    /// <summary>
    /// Gets the base64url-encoded authenticator data.
    /// </summary>
    [JsonPropertyName("authenticatorData")]
    public required string AuthenticatorData { get; init; }

    /// <summary>
    /// Gets the base64url-encoded signature created by the authenticator.
    /// </summary>
    [JsonPropertyName("signature")]
    public string? Signature { get; init; }

    /// <summary>
    /// Gets the base64url-encoded user handle (user ID) returned by the authenticator.
    /// </summary>
    [JsonPropertyName("userHandle")]
    public string? UserHandle { get; init; }
}
