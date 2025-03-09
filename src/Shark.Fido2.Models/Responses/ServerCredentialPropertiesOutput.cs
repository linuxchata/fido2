using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerCredentialPropertiesOutput
{
    [JsonPropertyName("rk")]
    public bool? RequireResidentKey { get; set; }
}
