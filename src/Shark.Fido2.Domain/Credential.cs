namespace Shark.Fido2.Domain;

public class Credential
{
    public required byte[] CredentialId { get; set; }

    /// <summary>
    /// Credential Public Key
    /// </summary>
    public required CredentialPublicKey CredentialPublicKey { get; set; }

    /// <summary>
    /// Signature Counter
    /// </summary>
    public uint SignCount { get; set; }

    public string[]? Transports { get; set; }
}
