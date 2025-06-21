namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 12.2.3.5 TPMS_RSA_PARMS
/// Trusted Platform Module Library.
/// </summary>
public sealed class TpmtPublicRsaParameters
{
    /// <summary>
    /// Gets key bits. Type is TPMI_RSA_KEY_BITS.
    /// </summary>
    public ushort KeyBits { get; init; }

    /// <summary>
    /// Gets exponent. Type is UINT32.
    /// </summary>
    public uint Exponent { get; init; }
}
