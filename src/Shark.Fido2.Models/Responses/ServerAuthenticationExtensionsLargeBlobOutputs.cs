using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Outputs for the Large Blob extension.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#sec-large-blob-extension.
public sealed class ServerAuthenticationExtensionsLargeBlobOutputs
{
    /// <summary>
    /// Gets a value indicating whether the authenticator supports the large blob extension.
    /// </summary>
    [JsonPropertyName("supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Supported { get; init; }

    /// <summary>
    /// Gets the base64url-encoded blob data read from the authenticator.
    /// </summary>
    [JsonPropertyName("blob")]
    public string? Blob { get; init; }

    /// <summary>
    /// Gets a value indicating whether the write was successful.
    /// </summary>
    [JsonPropertyName("written")]
    public bool? Written { get; init; }
}
