using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 5.4.2. Relying Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity)
/// See: https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrpentity.
/// </summary>
public sealed class ServerPublicKeyCredentialRpEntity
{
    [JsonPropertyName("id")]
    public required string Identifier { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }
}