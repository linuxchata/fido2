namespace Shark.Fido2.Domain;

public sealed class Credential
{
    public required byte[] CredentialId { get; set; }

    public required string Username { get; set; }

    public required CredentialPublicKey CredentialPublicKey { get; set; }

    public uint SignCount { get; set; }

    public string[]? Transports { get; set; }
}
