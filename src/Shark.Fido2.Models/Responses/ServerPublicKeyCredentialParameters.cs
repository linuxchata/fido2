﻿using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

public sealed class ServerPublicKeyCredentialParameters
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = null!;

    [JsonPropertyName("alg")]
    public long Algorithm { get; set; }
}
