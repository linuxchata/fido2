namespace Shark.Fido2.Sample.Blazor.Client.ViewModels;

public class CredentialDetailsViewModel
{
    public string CredentialId { get; init; } = null!;

    public string UserHandle { get; init; } = null!;

    public string UserName { get; init; } = null!;

    public string UserDisplayName { get; init; } = null!;

    public uint SignCount { get; init; }

    public string Algorithm { get; init; } = null!;

    public string[] Transports { get; init; } = null!;

    public DateTime CreatedAt { get; init; }

    public DateTime? UpdatedAt { get; init; }

    public DateTime? LastUsedAt { get; init; }
}