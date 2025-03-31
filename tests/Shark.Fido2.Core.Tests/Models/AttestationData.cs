using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Tests.Models;

internal sealed class AttestationData
{
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    [JsonPropertyName("rawId")]
    public required string RawId { get; set; }

    [JsonPropertyName("response")]
    public required AttestationResponseData Response { get; set; }

    [JsonPropertyName("type")]
    public required string Type { get; set; }
}
