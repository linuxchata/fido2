using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Inputs for the Large Blob extension.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#sec-large-blob-extension.
public sealed class ServerAuthenticationExtensionsLargeBlobInputs
{
    /// <summary>
    /// Gets the support preference.
    /// </summary>
    [JsonPropertyName("support")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Support { get; init; }

    /// <summary>
    /// Gets a value indicating whether to read the large blob.
    /// </summary>
    [JsonPropertyName("read")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Read { get; init; }

    /// <summary>
    /// Gets the base64url-encoded data to write to the large blob.
    /// </summary>
    [JsonPropertyName("write")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Write { get; init; }
}
