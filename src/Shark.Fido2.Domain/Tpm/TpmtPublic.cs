using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 12.2.4 TPMT_PUBLIC
/// Trusted Platform Module Library.
/// </summary>
public sealed class TpmtPublic
{
    /// <summary>
    /// Type is TPMI_ALG_PUBLIC.
    /// </summary>
    public ushort TypeRaw { get; init; }

    /// <summary>
    /// Type is TPMI_ALG_PUBLIC.
    /// </summary>
    public TpmAlgorithmEnum Type { get; init; }

    /// <summary>
    /// Type is TPMI_ALG_HASH.
    /// </summary>
    public TpmAlgorithmEnum NameAlg { get; init; }

    /// <summary>
    /// Type is TPMI_ALG_HASH.
    /// </summary>
    public ushort NameAlgRaw { get; init; }

    /// <summary>
    /// Type is TPMA_OBJECT.
    /// </summary>
    public uint ObjectAttributes { get; init; }

    /// <summary>
    /// Type is TPM2B_DIGEST.
    /// </summary>
    public required byte[] AuthPolicy { get; init; }

    /// <summary>
    /// Type is TPMU_PUBLIC_PARMS.
    /// </summary>
    public TpmtPublicRsaParameters? RsaParameters { get; init; }

    /// <summary>
    /// Type is TPMU_PUBLIC_PARMS.
    /// </summary>
    public TpmtPublicEccParameters? EccParameters { get; init; }

    /// <summary>
    /// Type is TPMU_PUBLIC_ID.
    /// </summary>
    public byte[]? Unique { get; init; }
}
