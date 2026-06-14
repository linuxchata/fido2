using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Public key credential parameters.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#dictionary-credential-params.
public sealed class ServerPublicKeyCredentialParameters
{
    /// <summary>
    /// Gets the credential type.
    /// </summary>
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    /// <summary>
    /// Gets the COSE cryptographic algorithm identifier.
    /// </summary>
    [JsonPropertyName("alg")]
    public long Algorithm { get; init; }
}
