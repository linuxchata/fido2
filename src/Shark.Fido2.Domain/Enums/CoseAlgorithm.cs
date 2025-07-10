namespace Shark.Fido2.Domain.Enums;

/// <summary>
/// COSE Algorithms
/// See: https://www.iana.org/assignments/cose/cose.xhtml#algorithms.
/// </summary>
public enum CoseAlgorithm
{
    /// <summary>
    /// ECDSA w/ SHA-256
    /// </summary>
    Es256 = -7,

    /// <summary>
    /// EdDSA
    /// </summary>
    EdDsa = -8,

    /// <summary>
    /// ECDSA w/ SHA-384
    /// </summary>
    Es384 = -35,

    /// <summary>
    /// ECDSA w/ SHA-512
    /// </summary>
    Es512 = -36,

    /// <summary>
    /// RSASSA-PSS w/ SHA-256
    /// </summary>
    Ps256 = -37,

    /// <summary>
    /// RSASSA-PSS w/ SHA-384
    /// </summary>
    Ps384 = -38,

    /// <summary>
    /// RSASSA-PSS w/ SHA-512
    /// </summary>
    Ps512 = -39,

    /// <summary>
    /// ECDSA using secp256k1 curve and SHA-256
    /// </summary>
    Es256K = -47,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    Rs256 = -257,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-384
    /// </summary>
    Rs384 = -258,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-512
    /// </summary>
    Rs512 = -259,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-1
    /// </summary>
    Rs1 = -65535,
}
