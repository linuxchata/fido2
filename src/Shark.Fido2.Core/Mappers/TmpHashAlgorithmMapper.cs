using System.Security.Cryptography;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Mappers;

public static class TmpHashAlgorithmMapper
{
    public static HashAlgorithmName Get(TpmAlgorithm tpmAlgorithm)
    {
        if (tpmAlgorithm == TpmAlgorithm.TpmAlgorithmSha1)
        {
            return HashAlgorithmName.SHA1;
        }
        else if (tpmAlgorithm == TpmAlgorithm.TpmAlgorithmSha256)
        {
            return HashAlgorithmName.SHA256;
        }
        else if (tpmAlgorithm == TpmAlgorithm.TpmAlgorithmSha384)
        {
            return HashAlgorithmName.SHA384;
        }
        else if (tpmAlgorithm == TpmAlgorithm.TpmAlgorithmSha512)
        {
            return HashAlgorithmName.SHA512;
        }
        else
        {
            throw new NotSupportedException($"Unsupported TPM algorithm {tpmAlgorithm}");
        }
    }
}
