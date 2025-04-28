namespace Shark.Fido2.Domain;

public sealed class CredentialDescriptor
{
    public required byte[] CredentialId { get; set; }

    public string[]? Transports { get; set; }
}
