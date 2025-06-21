using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain.Tpm;

/// <summary>
/// 12.2.4 TPMT_PUBLIC
/// Trusted Platform Module Library.
/// </summary>
public sealed class TpmtPublic
{
    /// <summary>
    /// Gets type raw. Type is TPMI_ALG_PUBLIC.
    /// </summary>
    public ushort TypeRaw { get; init; }

    /// <summary>
    /// Gets type. Type is TPMI_ALG_PUBLIC.
    /// </summary>
    public TpmAlgorithmEnum Type { get; init; }

    /// <summary>
    /// Gets name alg. Type is TPMI_ALG_HASH.
    /// </summary>
    public TpmAlgorithmEnum NameAlg { get; init; }

    /// <summary>
    /// Gets name alg raw. Type is TPMI_ALG_HASH.
    /// </summary>
    public ushort NameAlgRaw { get; init; }

    /// <summary>
    /// Gets object attributes. Type is TPMA_OBJECT.
    /// </summary>
    public uint ObjectAttributes { get; init; }

    /// <summary>
    /// Gets auth policy. Type is TPM2B_DIGEST.
    /// </summary>
    public required byte[] AuthPolicy { get; init; }

    /// <summary>
    /// Gets RSA parameters. Type is TPMU_PUBLIC_PARMS.
    /// </summary>
    public TpmtPublicRsaParameters? RsaParameters { get; init; }

    /// <summary>
    /// Gets Ecc parameters. Type is TPMU_PUBLIC_PARMS.
    /// </summary>
    public TpmtPublicEccParameters? EccParameters { get; init; }

    /// <summary>
    /// Gets unique. Type is TPMU_PUBLIC_ID.
    /// </summary>
    public byte[]? Unique { get; init; }
}
