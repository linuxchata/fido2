using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Requests;

/// <summary>
/// 5.4.4. Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)
/// See: https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection.
/// </summary>
public sealed class ServerAuthenticatorSelectionCriteriaRequest
{
    [JsonPropertyName("authenticatorAttachment")]
    public string? AuthenticatorAttachment { get; init; }

    [JsonPropertyName("residentKey")]
    public string? ResidentKey { get; init; }

    [JsonPropertyName("requireResidentKey")]
    public bool RequireResidentKey { get; init; } = false;

    [JsonPropertyName("userVerification")]
    public string? UserVerification { get; init; }
}