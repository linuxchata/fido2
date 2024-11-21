﻿using System.Text.Json.Serialization;

namespace Shark.Fido2.Responses;

public sealed class CredentialValidateResponse
{
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; set; }
}