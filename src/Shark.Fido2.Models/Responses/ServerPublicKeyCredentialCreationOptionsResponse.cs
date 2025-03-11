using System.Text.Json.Serialization;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 7.3.3.2. ServerPublicKeyCredentialCreationOptionsResponse
/// See: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsresponse
/// </summary>
public sealed class ServerPublicKeyCredentialCreationOptionsResponse : ServerResponse
{
    [JsonPropertyName("rp")]
    public ServerPublicKeyCredentialRpEntity RelyingParty { get; set; } = null!;

    [JsonPropertyName("user")]
    public ServerPublicKeyCredentialUserEntity User { get; set; } = null!;

    [JsonPropertyName("pubKeyCredParams")]
    public ServerPublicKeyCredentialParameters[] Parameters { get; set; } = null!;

    [JsonPropertyName("challenge")]
    public string Challenge { get; set; } = null!;

    [JsonPropertyName("timeout")]
    public ulong Timeout { get; set; }

    [JsonPropertyName("excludeCredentials")]
    public ServerPublicKeyCredentialDescriptor[] ExcludeCredentials { get; set; } = null!;

    [JsonPropertyName("authenticatorSelection")]
    public ServerAuthenticatorSelectionCriteria AuthenticatorSelection { get; set; } = null!;

    [JsonPropertyName("attestation")]
    public string Attestation { get; set; } = null!;

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ServerAuthenticationExtensionsClientInputs? Extensions { get; set; }
}