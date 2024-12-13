using System.Text.Json.Serialization;
using Shark.Fido2.Core.Constants;

namespace Shark.Sample.Fido2.Responses;

public class ServerPublicKeyCredentialCreationOptionsRequest
{
    [JsonPropertyName("username")]
    public required string Username { get; set; }

    [JsonPropertyName("displayName")]
    public required string DisplayName { get; set; }

    [JsonPropertyName("authenticatorSelection")]
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; set; }

    [JsonPropertyName("attestation")]
    public string Attestation { get; set; } = AttestationConveyancePreference.None;
}