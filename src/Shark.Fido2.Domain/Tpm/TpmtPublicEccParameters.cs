namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 12.2.3.6 TPMS_ECC_PARMS
/// Trusted Platform Module Library.
/// </summary>
public class TpmtPublicEccParameters
{
    /// <summary>
    /// Type is TPMI_ECC_CURVE.
    /// </summary>
    public ushort CurveId { get; init; }

    /// <summary>
    /// Type is TPMT_KDF_SCHEME.
    /// </summary>
    public ushort Kdf { get; init; }
}
