using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerAuthenticationExtensionsLargeBlobInputs
{
    [JsonPropertyName("support")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Support { get; init; }

    [JsonPropertyName("read")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Read { get; init; }

    [JsonPropertyName("write")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte[]? Write { get; init; }
}
