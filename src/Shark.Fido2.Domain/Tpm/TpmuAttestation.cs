namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 10.12.7 TPMU_ATTEST
/// Trusted Platform Module Library
/// </summary>
public sealed class TpmuAttestation
{
    /// <summary>
    /// Type is TPMS_CERTIFY_INFO
    /// </summary>
    public required byte[] Certify { get; init; }
}
