﻿using System.Text.Json.Serialization;

namespace Shark.Fido2.Requests;

public sealed class ServerAuthenticatorAttestationResponse
{
    [JsonPropertyName("clientDataJSON")]
    public required string ClientDataJson { get; set; }

    [JsonPropertyName("attestationObject")]
    public required string AttestationObject { get; set; }

    [JsonPropertyName("signature")]
    public string? Signature { get; set; }

    [JsonPropertyName("userHandler")]
    public string? UserHandler { get; set; }
}