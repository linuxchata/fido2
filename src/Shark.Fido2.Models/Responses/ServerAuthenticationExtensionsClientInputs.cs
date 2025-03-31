using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 5.7.1. Authentication Extensions Client Inputs (dictionary AuthenticationExtensionsClientInputs)
/// See: https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-inputs.
/// </summary>
public sealed class ServerAuthenticationExtensionsClientInputs
{
    [JsonPropertyName("credProps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? CredentialProperties { get; init; }

    [JsonPropertyName("example.extension.bool")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Example { get; init; }
}
