using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Public key credential user entity.
/// </summary>
// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialuserentity.
public sealed class ServerPublicKeyCredentialUserEntity
{
    /// <summary>
    /// Gets the unique user handle (user ID) of the user entity, base64url-encoded.
    /// </summary>
    [JsonPropertyName("id")]
    public required string Identifier { get; init; }

    /// <summary>
    /// Gets the username/name of the user (e.g., email address).
    /// </summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>
    /// Gets the friendly/display name of the user.
    /// </summary>
    [JsonPropertyName("displayName")]
    public required string DisplayName { get; init; }
}
