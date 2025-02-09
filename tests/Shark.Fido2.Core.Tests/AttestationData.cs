using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Tests;

public sealed class AttestationData
{
    [JsonPropertyName("attestationObject")]
    public required string AttestationObject { get; set; }

    [JsonPropertyName("clientDataJson")]
    public required string ClientDataJson { get; set; }
}
