using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerAuthenticationExtensionsClientInputs
{
    [JsonPropertyName("credProps")]
    public bool? CredentialProperties { get; set; }
}
