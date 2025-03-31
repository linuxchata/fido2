using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.3.3.2. ServerPublicKeyCredentialCreationOptionsResponse
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsresponse.
/// </summary>
public sealed class ServerPublicKeyCredentialCreationOptionsResponse : ServerResponse
{
    [JsonPropertyName("rp")]
    public required ServerPublicKeyCredentialRpEntity RelyingParty { get; init; }

    [JsonPropertyName("user")]
    public required ServerPublicKeyCredentialUserEntity User { get; init; }

    [JsonPropertyName("pubKeyCredParams")]
    public required ServerPublicKeyCredentialParameters[] Parameters { get; init; }

    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    [JsonPropertyName("timeout")]
    public ulong Timeout { get; init; }

    [JsonPropertyName("excludeCredentials")]
    public required ServerPublicKeyCredentialDescriptor[] ExcludeCredentials { get; init; }

    [JsonPropertyName("authenticatorSelection")]
    public required ServerAuthenticatorSelectionCriteria AuthenticatorSelection { get; init; }

    [JsonPropertyName("attestation")]
    public required string Attestation { get; init; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ServerAuthenticationExtensionsClientInputs? Extensions { get; init; }
}