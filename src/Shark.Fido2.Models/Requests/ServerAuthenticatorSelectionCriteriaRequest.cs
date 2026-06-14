using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Requests;

/// <summary>
/// Authenticator selection criteria request.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection.
public sealed class ServerAuthenticatorSelectionCriteriaRequest
{
    /// <summary>
    /// Gets the preferred authenticator attachment modality.
    /// </summary>
    [JsonPropertyName("authenticatorAttachment")]
    public string? AuthenticatorAttachment { get; init; }

    /// <summary>
    /// Gets the requirement for a client-side discoverable credential (resident key).
    /// </summary>
    [JsonPropertyName("residentKey")]
    public string? ResidentKey { get; init; }

    /// <summary>
    /// Gets a value indicating whether a client-side discoverable credential (resident key) is required.
    /// This is a legacy parameter and is overridden by <see cref="ResidentKey"/> if present.
    /// </summary>
    [JsonPropertyName("requireResidentKey")]
    public bool RequireResidentKey { get; init; } = false;

    /// <summary>
    /// Gets the Relying Party's requirement for user verification.
    /// </summary>
    [JsonPropertyName("userVerification")]
    public string? UserVerification { get; init; }
}
