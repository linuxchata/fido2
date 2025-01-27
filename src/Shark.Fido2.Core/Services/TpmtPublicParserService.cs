using System.Buffers.Binary;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Services;

public sealed class TpmtPublicParserService : ITpmtPublicParserService
{
    public TpmtPublic Parse(byte[] pubArea)
    {
        ArgumentNullException.ThrowIfNull(pubArea, nameof(pubArea));

        using var stream = new MemoryStream(pubArea);
        using var reader = new BinaryReader(stream);

        // TPMT_PUBLIC
        var tpmtPublic = new TpmtPublic();

        // TPMI_ALG_PUBLIC => TPM_ALG_ID; UINT16
        tpmtPublic.Type = (TpmAlgorithmEnum)ReadUInt16(reader);

        // TPMI_ALG_HASH => TPM_ALG_ID; UINT16
        tpmtPublic.NameAlg = ReadUInt16(reader);

        // TPMA_OBJECT; UINT32
        tpmtPublic.ObjectAttributes = ReadUInt32(reader);

        // TPM2B_DIGEST; size is UINT16
        var authPolicySize = ReadUInt16(reader);
        tpmtPublic.AuthPolicy = reader.ReadBytes(authPolicySize);

        if (tpmtPublic.Type == TpmAlgorithmEnum.TpmAlgorithmRsa)
        {
            var symmetric = ReadUInt16(reader);
            var scheme = ReadUInt16(reader);

            // TPMI_RSA_KEY_BITS => TPM_KEY_BITS; UINT16
            tpmtPublic.RsaParameters.KeyBits = ReadUInt16(reader);

            // TPMS_RSA_PARMS; UINT32
            var exponent = ReadUInt32(reader);
            if (exponent == 0)
            {
                exponent = (uint)(Math.Pow(2, 16) + 1);
            }
            tpmtPublic.RsaParameters.Exponent = exponent;

            // TPMU_PUBLIC_ID
            var size = ReadUInt16(reader);
            tpmtPublic.Unique = reader.ReadBytes(size);
        }

        return tpmtPublic;
    }

    private static ushort ReadUInt16(BinaryReader reader)
    {
        return BinaryPrimitives.ReadUInt16BigEndian(reader.ReadBytes(2));
    }

    private static uint ReadUInt32(BinaryReader reader)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(reader.ReadBytes(4));
    }
}
