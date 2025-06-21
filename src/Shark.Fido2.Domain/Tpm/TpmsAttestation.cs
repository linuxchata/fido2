namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 10.12.8 TPMS_ATTEST
/// Trusted Platform Module Library.
/// </summary>
public sealed class TpmsAttestation
{
    /// <summary>
    /// Gets magic. Type is TPM_GENERATED.
    /// </summary>
    public uint Magic { get; init; }

    /// <summary>
    /// Gets type. Type is TPMI_ST_ATTEST.
    /// </summary>
    public ushort Type { get; init; }

    /// <summary>
    /// Gets qualified signer. Type is TPM2B_NAME.
    /// </summary>
    public required byte[] QualifiedSigner { get; init; }

    /// <summary>
    /// Gets extra data. Type is TPM2B_DATA.
    /// </summary>
    public required byte[] ExtraData { get; init; }

    /// <summary>
    /// Gets clock info. Type is TPMS_CLOCK_INFO.
    /// </summary>
    public required TpmsClockInfo ClockInfo { get; init; }

    /// <summary>
    /// Gets firmware version. Type is UINT64.
    /// </summary>
    public ulong FirmwareVersion { get; init; }

    /// <summary>
    /// Gets attested. Type is TPMU_ATTEST.
    /// </summary>
    public required TpmuAttestation Attested { get; init; }
}
