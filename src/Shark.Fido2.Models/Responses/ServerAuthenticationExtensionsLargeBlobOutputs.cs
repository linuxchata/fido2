using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerAuthenticationExtensionsLargeBlobOutputs
{
    [JsonPropertyName("supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Supported { get; init; }

    [JsonPropertyName("blob")]
    public byte[]? Blob { get; init; }

    [JsonPropertyName("written")]
    public bool? Written { get; init; }
}
