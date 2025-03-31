using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.3.4.2. ServerPublicKeyCredentialUserEntity
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialuserentity.
/// </summary>
public sealed class ServerPublicKeyCredentialUserEntity
{
    [JsonPropertyName("id")]
    public required string Identifier { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("displayName")]
    public required string DisplayName { get; init; }
}
