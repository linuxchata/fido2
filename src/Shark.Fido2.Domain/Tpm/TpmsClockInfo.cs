namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 10.11.1 TPMS_CLOCK_INFO
/// Trusted Platform Module Library.
/// </summary>
public sealed class TpmsClockInfo
{
    /// <summary>
    /// Type is UINT64.
    /// </summary>
    public ulong Clock { get; set; }

    /// <summary>
    /// Type is UINT32.
    /// </summary>
    public uint ResetCount { get; set; }

    /// <summary>
    /// Type is UINT32.
    /// </summary>
    public uint RestartCount { get; set; }

    /// <summary>
    /// Type is TPMI_YES_NO.
    /// </summary>
    public bool Safe { get; set; }
}
