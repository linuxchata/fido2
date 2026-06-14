using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Requests;

/// <summary>
/// Public key credential get options request.
/// </summary>
// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialgetoptionsrequest.
public sealed class ServerPublicKeyCredentialGetOptionsRequest
{
    /// <summary>
    /// Gets a human-readable name for the entity.
    /// </summary>
    [JsonPropertyName("username")]
    public string? Username { get; init; }

    /// <summary>
    /// Gets the Relying Party's requirement for user verification.
    /// </summary>
    [JsonPropertyName("userVerification")]
    public string? UserVerification { get; init; }
}
