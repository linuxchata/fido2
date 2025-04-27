namespace Shark.Fido2.Domain.Options;

/// <summary>
/// 5.4.3. User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)
/// See: https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialuserentity.
/// </summary>
public sealed class PublicKeyCredentialUserEntity
{
    public required byte[] Id { get; init; }

    public required string Name { get; init; }

    public required string DisplayName { get; init; }
}
