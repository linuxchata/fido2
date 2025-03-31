using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 10.4. Credential Properties Extension (credProps)
/// See: https://www.w3.org/TR/webauthn-2/#dictdef-credentialpropertiesoutput.
/// </summary>
public sealed class ServerCredentialPropertiesOutput
{
    [JsonPropertyName("rk")]
    public bool? RequireResidentKey { get; init; }
}
