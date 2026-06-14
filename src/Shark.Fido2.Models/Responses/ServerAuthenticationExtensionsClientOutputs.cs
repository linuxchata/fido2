using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Authentication extensions client outputs.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-outputs.
public sealed class ServerAuthenticationExtensionsClientOutputs
{
    /// <summary>
    /// Gets a value indicating whether the AppID extension was successfully verified.
    /// </summary>
    [JsonPropertyName("appid")]
    public bool? AppId { get; init; }

    /// <summary>
    /// Gets a value indicating whether the AppID Exclude extension was successfully matched.
    /// </summary>
    [JsonPropertyName("appidExclude")]
    public bool? AppIdExclude { get; init; }

    /// <summary>
    /// Gets the user verification method information.
    /// </summary>
    [JsonPropertyName("uvm")]
    public IEnumerable<ulong[]>? UserVerificationMethod { get; init; }

    /// <summary>
    /// Gets the credential properties returned by the client.
    /// </summary>
    [JsonPropertyName("credProps")]
    public ServerCredentialPropertiesOutput? CredentialProperties { get; init; }

    /// <summary>
    /// Gets the outputs of the Large Blob extension.
    /// </summary>
    [JsonPropertyName("largeBlob")]
    public ServerAuthenticationExtensionsLargeBlobOutputs? LargeBlob { get; init; }
}
