namespace Shark.Fido2.Domain;

/// <summary>
/// 5.4.2. Relying Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity)
/// See: https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrpentity.
/// </summary>
public sealed class PublicKeyCredentialRpEntity
{
    public required string Id { get; init; }

    public required string Name { get; init; }
}
