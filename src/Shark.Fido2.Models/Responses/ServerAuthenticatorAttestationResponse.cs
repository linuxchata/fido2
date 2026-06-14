using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Authenticator attestation response.
/// </summary>
// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverauthenticatorattestationresponse.
public sealed class ServerAuthenticatorAttestationResponse : ServerAuthenticatorResponse
{
    /// <summary>
    /// Gets the base64url-encoded JSON-serialized client data.
    /// </summary>
    [JsonPropertyName("clientDataJSON")]
    public required string ClientDataJson { get; init; }

    /// <summary>
    /// Gets the base64url-encoded attestation object containing the authenticator data and attestation statement.
    /// </summary>
    [JsonPropertyName("attestationObject")]
    public required string AttestationObject { get; init; }

    /// <summary>
    /// Gets the communication transports supported/used by the authenticator.
    /// </summary>
    [JsonPropertyName("transports")]
    public string[]? Transports { get; init; }
}
