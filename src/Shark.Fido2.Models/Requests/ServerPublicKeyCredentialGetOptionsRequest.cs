using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Requests;

/// <summary>
/// 7.4.3.1. ServerPublicKeyCredentialGetOptionsRequest
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialgetoptionsrequest.
/// </summary>
public sealed class ServerPublicKeyCredentialGetOptionsRequest
{
    [JsonPropertyName("username")]
    public string? Username { get; set; } // Optional

    [JsonPropertyName("userVerification")]
    public string? UserVerification { get; set; }
}
