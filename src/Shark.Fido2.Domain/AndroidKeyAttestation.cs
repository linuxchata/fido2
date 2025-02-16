using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain;

public sealed class AndroidKeyAttestation
{
    public int AttestationVersion { get; init; }

    public AndroidKeySecurityLevel AttestationSecurityLevel { get; init; }

    public int KeymasterVersion { get; init; }

    public AndroidKeySecurityLevel KeymasterSecurityLevel { get; init; }

    public byte[] AttestationChallenge { get; init; } = [];

    public byte[] UniqueId { get; init; } = [];

    public byte[] SoftwareEnforced { get; init; } = [];

    public byte[] HardwareEnforced { get; init; } = [];
}
