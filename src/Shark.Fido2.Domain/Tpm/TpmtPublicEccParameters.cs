namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 12.2.3.6 TPMS_ECC_PARMS
/// Trusted Platform Module Library.
/// </summary>
public class TpmtPublicEccParameters
{
    /// <summary>
    /// Gets curve id. Type is TPMI_ECC_CURVE.
    /// </summary>
    public ushort CurveId { get; init; }

    /// <summary>
    /// Gets KDF. Type is TPMT_KDF_SCHEME.
    /// </summary>
    public ushort Kdf { get; init; }
}
