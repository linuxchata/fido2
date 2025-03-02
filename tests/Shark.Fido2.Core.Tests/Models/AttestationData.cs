using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Tests.Models;

internal sealed class AttestationData
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = null!;

    [JsonPropertyName("rawId")]
    public string RawId { get; set; } = null!;

    [JsonPropertyName("response")]
    public AttestationResponseData Response { get; set; } = null!;

    [JsonPropertyName("type")]
    public string Type { get; set; } = null!;
}
