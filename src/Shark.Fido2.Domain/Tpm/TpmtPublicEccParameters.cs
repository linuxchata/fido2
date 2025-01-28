namespace Shark.Fido2.Domain.Tpm;

public class TpmtPublicEccParameters
{
    /// <summary>
    /// Type is TPMI_ECC_CURVE
    /// </summary>
    public ushort CurveId { get; init; }

    /// <summary>
    /// Type is TPMT_KDF_SCHEME
    /// </summary>
    public ushort Kdf { get; init; }
}
