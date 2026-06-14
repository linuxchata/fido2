using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// Authentication extensions client inputs.
/// </summary>
// See: https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-inputs.
public sealed class ServerAuthenticationExtensionsClientInputs
{
    /// <summary>
    /// Gets the FIDO AppID extension identifier.
    /// This allows a Relying Party to specify the AppID of a legacy FIDO U2F credential.
    /// </summary>
    [JsonPropertyName("appid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AppId { get; init; }

    /// <summary>
    /// Gets the AppID Exclude extension.
    /// This allows a Relying Party to specify an AppID to check for existing credentials during registration.
    /// </summary>
    [JsonPropertyName("appidExclude")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AppIdExclude { get; init; }

    /// <summary>
    /// Gets a value indicating whether the client should return the User Verification Method (uvm) extension output.
    /// </summary>
    [JsonPropertyName("uvm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UserVerificationMethod { get; init; }

    /// <summary>
    /// Gets a value indicating whether the client should return the Credential Properties (credProps) extension output.
    /// </summary>
    [JsonPropertyName("credProps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? CredentialProperties { get; init; }

    /// <summary>
    /// Gets the input parameters for the Large Blob extension.
    /// </summary>
    [JsonPropertyName("largeBlob")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ServerAuthenticationExtensionsLargeBlobInputs? LargeBlob { get; init; }

    /// <summary>
    /// Gets an example boolean extension value.
    /// </summary>
    [JsonPropertyName("example.extension.bool")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Example { get; init; }
}
