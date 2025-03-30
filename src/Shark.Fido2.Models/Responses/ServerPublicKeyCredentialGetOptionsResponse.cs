using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.4.3.2. ServerPublicKeyCredentialGetOptionsResponse
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialgetoptionsresponse.
/// </summary>
public sealed class ServerPublicKeyCredentialGetOptionsResponse : ServerResponse
{
    [JsonPropertyName("challenge")]
    public string Challenge { get; set; } = null!;

    [JsonPropertyName("timeout")]
    public ulong? Timeout { get; set; }

    [JsonPropertyName("rpId")]
    public string? RpId { get; set; }

    [JsonPropertyName("allowCredentials")]
    public ServerPublicKeyCredentialDescriptor[] AllowCredentials { get; set; } = null!;

    [JsonPropertyName("userVerification")]
    public string UserVerification { get; set; } = null!;

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ServerAuthenticationExtensionsClientInputs? Extensions { get; set; }
}
