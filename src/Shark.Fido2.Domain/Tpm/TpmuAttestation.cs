namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 10.12.7 TPMU_ATTEST
/// Trusted Platform Module Library.
/// </summary>
public sealed class TpmuAttestation
{
    /// <summary>
    /// Type is TPM2B_NAME.
    /// </summary>
    public required byte[] Name { get; init; }

    /// <summary>
    /// Type is TPM2B_NAME.
    /// </summary>
    public required byte[] QualifiedName { get; init; }
}
