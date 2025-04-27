namespace Shark.Fido2.Core.Entities;

public sealed class CredentialEntity
{
    public required byte[] CredentialId { get; set; }

    public required byte[] UserHandle { get; set; }

    public required string Username { get; set; }

    public required CredentialPublicKeyEntity CredentialPublicKey { get; set; }

    public uint SignCount { get; set; }

    public string[]? Transports { get; set; }
}
