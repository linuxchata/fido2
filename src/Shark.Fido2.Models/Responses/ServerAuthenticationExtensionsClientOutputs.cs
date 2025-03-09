using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerAuthenticationExtensionsClientOutputs
{
    [JsonPropertyName("credProps")]
    public ServerCredentialPropertiesOutput? CredentialProperties { get; set; }
}
