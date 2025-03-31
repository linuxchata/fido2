using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.4.3.2. ServerPublicKeyCredentialGetOptionsResponse
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialgetoptionsresponse.
/// </summary>
public sealed class ServerPublicKeyCredentialGetOptionsResponse : ServerResponse
{
    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    [JsonPropertyName("timeout")]
    public ulong? Timeout { get; init; }

    [JsonPropertyName("rpId")]
    public string? RpId { get; init; }

    [JsonPropertyName("allowCredentials")]
    public required ServerPublicKeyCredentialDescriptor[] AllowCredentials { get; init; }

    [JsonPropertyName("userVerification")]
    public required string UserVerification { get; init; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ServerAuthenticationExtensionsClientInputs? Extensions { get; init; }
}
