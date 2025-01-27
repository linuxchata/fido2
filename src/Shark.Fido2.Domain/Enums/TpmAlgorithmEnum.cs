namespace Shark.Fido2.Domain.Enums;

/// <summary>
/// TPM Algorithm Types
/// </summary>
public enum TpmAlgorithmEnum
{
    /// <summary>
    /// TPM_ALG_ERROR (0x0000)
    /// </summary>
    TpmAlgorithmError = 0x0000,

    /// <summary>
    /// TPM_ALG_RSA (0x0001)
    /// </summary>
    TpmAlgorithmRsa = 0x0001,

    /// <summary>
    /// TPM_ALG_SHA (0x0004)
    /// </summary>
    TpmAlgorithmSha = 0x0004,

    /// <summary>
    /// TPM_ALG_SHA1 (0x0004)
    /// </summary>
    TpmAlgorithmSha1 = 0x0004,

    /// <summary>
    /// TPM_ALG_HMAC (0x0005)
    /// </summary>
    TpmAlgorithmHmac = 0x0005,

    /// <summary>
    /// TPM_ALG_AES (0x0006)
    /// </summary>
    TpmAlgorithmAes = 0x0006,

    /// <summary>
    /// TPM_ALG_MGF1 (0x0007)
    /// </summary>
    TpmAlgorithmMgf1 = 0x0007,

    /// <summary>
    /// TPM_ALG_KEYEDHASH (0x0008)
    /// </summary>
    TpmAlgorithmKeyedHash = 0x0008,

    /// <summary>
    /// TPM_ALG_XOR (0x000A)
    /// </summary>
    TpmAlgorithmXor = 0x000A,

    /// <summary>
    /// TPM_ALG_SHA256 (0x000B)
    /// </summary>
    TpmAlgorithmSha256 = 0x000B,

    /// <summary>
    /// TPM_ALG_SHA384 (0x000C)
    /// </summary>
    TpmAlgorithmSha384 = 0x000C,

    /// <summary>
    /// TPM_ALG_SHA512 (0x000D)
    /// </summary>
    TpmAlgorithmSha512 = 0x000D,

    /// <summary>
    /// TPM_ALG_NULL (0x0010)
    /// </summary>
    TpmAlgorithmNull = 0x0010,

    /// <summary>
    /// TPM_ALG_SM3_256 (0x0012)
    /// </summary>
    TpmAlgorithmSm3_256 = 0x0012,

    /// <summary>
    /// TPM_ALG_SM4 (0x0013)
    /// </summary>
    TpmAlgorithmSm4 = 0x0013,

    /// <summary>
    /// TPM_ALG_RSASSA (0x0014)
    /// </summary>
    TpmAlgorithmRsassa = 0x0014,

    /// <summary>
    /// TPM_ALG_RSAES (0x0015)
    /// </summary>
    TpmAlgorithmRsaes = 0x0015,

    /// <summary>
    /// TPM_ALG_RSAPSS (0x0016)
    /// </summary>
    TpmAlgorithmRsapss = 0x0016,

    /// <summary>
    /// TPM_ALG_OAEP (0x0017)
    /// </summary>
    TpmAlgorithmOaep = 0x0017,

    /// <summary>
    /// TPM_ALG_ECDSA (0x0018)
    /// </summary>
    TpmAlgorithmEcdsa = 0x0018,

    /// <summary>
    /// TPM_ALG_ECDH (0x0019)
    /// </summary>
    TpmAlgorithmEcdh = 0x0019,

    /// <summary>
    /// TPM_ALG_ECDAA (0x001A)
    /// </summary>
    TpmAlgorithmEcdaa = 0x001A,

    /// <summary>
    /// TPM_ALG_SM2 (0x001B)
    /// </summary>
    TpmAlgorithmSm2 = 0x001B,

    /// <summary>
    /// TPM_ALG_ECSCHNORR (0x001C)
    /// </summary>
    TpmAlgorithmEcschnorr = 0x001C,

    /// <summary>
    /// TPM_ALG_ECMQV (0x001D)
    /// </summary>
    TpmAlgorithmEcmqv = 0x001D,

    /// <summary>
    /// TPM_ALG_KDF1_SP800_56A (0x0020)
    /// </summary>
    TpmAlgorithmKdf1Sp800_56A = 0x0020,

    /// <summary>
    /// TPM_ALG_KDF2 (0x0021)
    /// </summary>
    TpmAlgorithmKdf2 = 0x0021,

    /// <summary>
    /// TPM_ALG_KDF1_SP800_108 (0x0022)
    /// </summary>
    TpmAlgorithmKdf1Sp800_108 = 0x0022,

    /// <summary>
    /// TPM_ALG_ECC (0x0023)
    /// </summary>
    TpmAlgorithmEcc = 0x0023,

    /// <summary>
    /// TPM_ALG_SYMCIPHER (0x0025)
    /// </summary>
    TpmAlgorithmSymcipher = 0x0025,

    /// <summary>
    /// TPM_ALG_CAMELLIA (0x0026)
    /// </summary>
    TpmAlgorithmCamellia = 0x0026,

    /// <summary>
    /// TPM_ALG_CTR (0x0040)
    /// </summary>
    TpmAlgorithmCtr = 0x0040,

    /// <summary>
    /// TPM_ALG_OFB (0x0041)
    /// </summary>
    TpmAlgorithmOfb = 0x0041,

    /// <summary>
    /// TPM_ALG_CBC (0x0042)
    /// </summary>
    TpmAlgorithmCbc = 0x0042,

    /// <summary>
    /// TPM_ALG_CFB (0x0043)
    /// </summary>
    TpmAlgorithmCfb = 0x0043,

    /// <summary>
    /// TPM_ALG_ECB (0x0044)
    /// </summary>
    TpmAlgorithmEcb = 0x0044
}
