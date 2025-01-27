using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 12.2.4 TPMT_PUBLIC
/// Trusted Platform Module Library
/// </summary>
public sealed class TpmtPublic
{
    public TpmtPublic()
    {
        RsaParameters = new TpmtPublicRsaParameters();
    }

    /// <summary>
    /// Type is TPMI_ALG_PUBLIC
    /// </summary>
    public TpmAlgorithmEnum Type { get; set; }

    /// <summary>
    /// Type is TPMI_ALG_HASH
    /// </summary>
    public ushort NameAlg { get; set; }

    /// <summary>
    /// Type is TPMA_OBJECT
    /// </summary>
    public uint ObjectAttributes { get; set; }

    /// <summary>
    /// Type is TPM2B_DIGEST
    /// </summary>
    public byte[]? AuthPolicy { get; set; }

    /// <summary>
    /// Type is TPMU_PUBLIC_PARMS
    /// </summary>
    public TpmtPublicRsaParameters RsaParameters { get; set; }

    /// <summary>
    /// Type is TPMU_PUBLIC_ID
    /// </summary>
    public byte[]? Unique { get; set; }
}
