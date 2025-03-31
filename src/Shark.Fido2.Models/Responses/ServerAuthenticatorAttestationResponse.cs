using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.3.3.3. ServerAuthenticatorAttestationResponse
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverauthenticatorattestationresponse.
/// </summary>
public sealed class ServerAuthenticatorAttestationResponse : ServerAuthenticatorResponse
{
    [JsonPropertyName("clientDataJSON")]
    public required string ClientDataJson { get; init; }

    [JsonPropertyName("attestationObject")]
    public required string AttestationObject { get; init; }

    [JsonPropertyName("transports")]
    public string[]? Transports { get; init; }
}