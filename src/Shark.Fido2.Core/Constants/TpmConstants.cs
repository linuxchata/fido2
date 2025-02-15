namespace Shark.Fido2.Core.Constants;

internal static class TpmConstants
{
    /// <summary>
    /// TPM_GENERATED_VALUE as specified in TPMv2-Part2
    /// </summary>
    public const uint TpmGeneratedValue = 0xff544347;

    /// <summary>
    /// TPM_ST_ATTEST_CERTIFY as specified in TPMv2-Part2
    /// </summary>
    public const ushort TpmStAttestCertify = 0x8017;
}
