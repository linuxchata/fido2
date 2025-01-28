using System.Buffers.Binary;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Services;

public sealed class TpmtPublicAreaParserService : ITpmtPublicAreaParserService
{
    public TpmtPublic Parse(byte[] pubArea)
    {
        ArgumentNullException.ThrowIfNull(pubArea, nameof(pubArea));

        using var stream = new MemoryStream(pubArea);
        using var reader = new BinaryReader(stream);

        // TPMI_ALG_PUBLIC => TPM_ALG_ID; UINT16
        var type = (TpmAlgorithmEnum)ReadUInt16(reader);

        // TPMI_ALG_HASH => TPM_ALG_ID; UINT16
        var nameAlg = ReadUInt16(reader);

        // TPMA_OBJECT; UINT32
        var objectAttributes = ReadUInt32(reader);

        // TPM2B_DIGEST; size is UINT16
        var authPolicySize = ReadUInt16(reader);
        var authPolicy = reader.ReadBytes(authPolicySize);

        /// TPMT_SYM_DEF_OBJECT
        var symmetric = ReadUInt16(reader);

        // TPMT_RSA_SCHEME or TPMT_ECC_SCHEME
        var scheme = ReadUInt16(reader);

        TpmtPublicRsaParameters tpmtPublicRsaParameters = null!;
        TpmtPublicEccParameters tpmtPublicEccParameters = null!;
        byte[]? unique = null;
        if (type == TpmAlgorithmEnum.TpmAlgorithmRsa)
        {
            // TPMI_RSA_KEY_BITS => TPM_KEY_BITS; UINT16
            var keyBits = ReadUInt16(reader);

            // TPMS_RSA_PARMS; UINT32
            var exponent = ReadUInt32(reader);
            if (exponent == 0)
            {
                exponent = (uint)(Math.Pow(2, 16) + 1);
            }

            tpmtPublicRsaParameters = new TpmtPublicRsaParameters
            {
                KeyBits = keyBits,
                Exponent = exponent,
            };

            // TPMU_PUBLIC_ID => TPM2B_PUBLIC_KEY_RSA
            var size = ReadUInt16(reader);
            unique = reader.ReadBytes(size);
        }
        else if (type == TpmAlgorithmEnum.TpmAlgorithmEcc)
        {
            // TPMI_ECC_CURVE => TPM_ECC_CURVE; UINT16
            var curveId = ReadUInt16(reader);

            // TPMT_KDF_SCHEME => TPMI_ALG_KDF => TPM_ALG_ID; UINT16
            var kdf = ReadUInt16(reader);

            tpmtPublicEccParameters = new TpmtPublicEccParameters
            {
                CurveId = curveId,
                Kdf = kdf,
            };

            // TPMU_PUBLIC_ID => TPMS_ECC_POINT
            // TPM2B_ECC_PARAMETER
            var sizeX = ReadUInt16(reader);
            var xCoordinate = reader.ReadBytes(sizeX);

            // TPM2B_ECC_PARAMETER
            var sizeY = ReadUInt16(reader);
            var yCoordinate = reader.ReadBytes(sizeY);

            unique = [.. xCoordinate, .. yCoordinate];
        }

        // TPMT_PUBLIC
        var tpmtPublic = new TpmtPublic
        {
            Type = type,
            NameAlg = nameAlg,
            ObjectAttributes = objectAttributes,
            AuthPolicy = authPolicy,
            RsaParameters = tpmtPublicRsaParameters,
            EccParameters = tpmtPublicEccParameters,
            Unique = unique,
        };

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
