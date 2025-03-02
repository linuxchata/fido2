using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Tests.Models;

internal sealed class AttestationResponseData
{
    [JsonPropertyName("attestationObject")]
    public required string AttestationObject { get; set; }

    [JsonPropertyName("clientDataJson")]
    public required string ClientDataJson { get; set; }
}
