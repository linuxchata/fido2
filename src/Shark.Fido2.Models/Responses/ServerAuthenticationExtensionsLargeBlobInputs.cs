using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerAuthenticationExtensionsLargeBlobInputs
{
    [JsonPropertyName("support")]
    public string? Support { get; set; }

    [JsonPropertyName("read")]
    public bool Read { get; set; }

    [JsonPropertyName("write")]
    public byte[]? Write { get; set; }
}
