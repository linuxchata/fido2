using Shark.Fido2.Domain.Enums;
using System.Security.Cryptography;

namespace Shark.Fido2.Domain.Mappers;

public sealed class GenericTmpHashAlgorithmMapper
{
    public static HashAlgorithmName Get(TpmAlgorithmEnum tpmAlgorithm)
    {
        if (tpmAlgorithm == TpmAlgorithmEnum.TpmAlgorithmSha1)
        {
            return HashAlgorithmName.SHA1;
        }
        else if (tpmAlgorithm == TpmAlgorithmEnum.TpmAlgorithmSha256)
        {
            return HashAlgorithmName.SHA256;
        }
        else if (tpmAlgorithm == TpmAlgorithmEnum.TpmAlgorithmSha384)
        {
            return HashAlgorithmName.SHA384;
        }
        else if (tpmAlgorithm == TpmAlgorithmEnum.TpmAlgorithmSha512)
        {
            return HashAlgorithmName.SHA512;
        }
        else
        {
            throw new NotSupportedException("Unsupported TPM algorithm");
        }
    }
}
