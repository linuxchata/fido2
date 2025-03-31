using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 5.3. Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)
/// See: https://www.w3.org/TR/webauthn-2/#dictionary-credential-params.
/// </summary>
public sealed class ServerPublicKeyCredentialParameters
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("alg")]
    public long Algorithm { get; init; }
}
