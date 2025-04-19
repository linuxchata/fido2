using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 5.7.2. Authentication Extensions Client Outputs (dictionary AuthenticationExtensionsClientOutputs)
/// See: https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-outputs.
/// </summary>
public sealed class ServerAuthenticationExtensionsClientOutputs
{
    [JsonPropertyName("appid")]
    public bool? AppId { get; init; }

    [JsonPropertyName("appidExclude")]
    public bool? AppIdExclude { get; init; }

    [JsonPropertyName("uvm")]
    public IEnumerable<ulong[]>? UserVerificationMethod { get; init; }

    [JsonPropertyName("credProps")]
    public ServerCredentialPropertiesOutput? CredentialProperties { get; init; }

    [JsonPropertyName("largeBlob")]
    public ServerAuthenticationExtensionsLargeBlobOutputs? LargeBlob { get; init; }
}
