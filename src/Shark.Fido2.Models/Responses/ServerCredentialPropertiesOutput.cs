using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Credential properties extension.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#dictdef-credentialpropertiesoutput.
public sealed class ServerCredentialPropertiesOutput
{
    /// <summary>
    /// Gets a value indicating whether the credential created is a client-side discoverable credential (resident key).
    /// </summary>
    [JsonPropertyName("rk")]
    public bool? RequireResidentKey { get; init; }
}
