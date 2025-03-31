using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.4.3.3. ServerAuthenticatorAssertionResponse
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverauthenticatorassertionresponse.
/// </summary>
public sealed class ServerAuthenticatorAssertionResponse : ServerAuthenticatorResponse
{
    [JsonPropertyName("clientDataJSON")]
    public required string ClientDataJson { get; init; }

    [JsonPropertyName("authenticatorData")]
    public required string AuthenticatorData { get; init; }

    [JsonPropertyName("signature")]
    public string? Signature { get; init; }

    [JsonPropertyName("userHandle")]
    public string? UserHandle { get; init; }
}
