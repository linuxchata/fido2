using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 5.4.4. Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)
/// See: https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection.
/// </summary>
public sealed class ServerAuthenticatorSelectionCriteria
{
    [JsonPropertyName("authenticatorAttachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthenticatorAttachment { get; init; }

    [JsonPropertyName("residentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResidentKey { get; init; }

    [JsonPropertyName("requireResidentKey")]
    public bool RequireResidentKey { get; init; }

    [JsonPropertyName("userVerification")]
    public required string UserVerification { get; init; }
}
