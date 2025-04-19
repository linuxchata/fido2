using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerAuthenticationExtensionsLargeBlobInputs
{
    [JsonPropertyName("support")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Support { get; set; }

    [JsonPropertyName("read")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Read { get; set; }

    [JsonPropertyName("write")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte[]? Write { get; set; }
}
