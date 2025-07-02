using System.Text.Json.Serialization;

namespace Shark.Fido2.Core.Entities;

public sealed class CredentialEntity
{
    public required byte[] CredentialId { get; set; }

    public required byte[] UserHandle { get; set; }

    public required string UserName { get; set; }

    public required string UserDisplayName { get; set; }

    public required CredentialPublicKeyEntity CredentialPublicKey { get; set; }

    [JsonIgnore]
    public string CredentialPublicKeyJson { get; set; } = null!;

    public uint SignCount { get; set; }

    public string? Transports { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public DateTime? LastUsedAt { get; set; }
}
