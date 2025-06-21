namespace Shark.Fido2.Core.Entities;

public sealed class CredentialDescriptorEntity
{
    public required byte[] CredentialId { get; set; }

    public required string UserName { get; set; }

    public string? Transports { get; set; }
}
