using System.Buffers.Binary;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Services;

internal sealed class TpmsAttestationParserService : ITpmsAttestationParserService
{
    public bool Parse(byte[] certInfo, out TpmsAttestation tpmsAttestation)
    {
        ArgumentNullException.ThrowIfNull(certInfo, nameof(certInfo));

        try
        {
            using var stream = new MemoryStream(certInfo);
            using var reader = new BinaryReader(stream);

            // TPM_GENERATED; UINT32
            var magic = ReadUInt32(reader);

            // TPMI_ST_ATTEST; UINT16
            var type = ReadUInt16(reader);

            // TPM2B_NAME; size is UINT16
            var qualifiedSignerSize = ReadUInt16(reader);
            var qualifiedSigner = reader.ReadBytes(qualifiedSignerSize);

            // TPM2B_DATA; size is UINT16
            var extraDataSize = ReadUInt16(reader);
            var extraData = reader.ReadBytes(extraDataSize);

            // TPMS_CLOCK_INFO
            // UINT64
            var clock = ReadUInt64(reader);

            // UINT32
            var resetCount = ReadUInt32(reader);

            // UINT32
            var restartCount = ReadUInt32(reader);

            // TPMI_YES_NO; BYTE
            var safe = reader.ReadBoolean();

            var tpmsClockInfo = new TpmsClockInfo
            {
                Clock = clock,
                ResetCount = resetCount,
                RestartCount = restartCount,
                Safe = safe,
            };

            // UINT64
            var firmwareVersion = ReadUInt64(reader);

            // TPMU_ATTEST
            // TPMS_CERTIFY_INFO => TPM2B_NAME; size is UINT16
            var certifyNameSize = ReadUInt16(reader);
            byte[]? certifyName = null;
            if (certifyNameSize > 0)
            {
                var certifyNamAlg = ReadUInt16(reader); // 2 bytes for TPM_ALG_ID
                certifyName = reader.ReadBytes(certifyNameSize - 2);
            }

            var certifyQualifiedNameSize = ReadUInt16(reader);
            byte[]? certifyQualifiedName = null;
            if (certifyQualifiedNameSize > 0)
            {
                var certifyQualifiedNameAlg = ReadUInt16(reader); // 2 bytes for TPM_ALG_ID
                certifyQualifiedName = reader.ReadBytes(certifyQualifiedNameSize - 2);
            }

            var tpmuAttestation = new TpmuAttestation
            {
                Name = certifyName ?? [],
                QualifiedName = certifyQualifiedName ?? [],
            };

            if (reader.BaseStream.Position != reader.BaseStream.Length)
            {
                throw new InvalidOperationException("Error reading certInfo byte array");
            }

            tpmsAttestation = new TpmsAttestation
            {
                Magic = magic,
                Type = type,
                QualifiedSigner = qualifiedSigner,
                ExtraData = extraData,
                ClockInfo = tpmsClockInfo,
                FirmwareVersion = firmwareVersion,
                Attested = tpmuAttestation,
            };
        }
        catch (Exception)
        {
            tpmsAttestation = default!;
            return false;
        }

        return true;
    }

    private static ushort ReadUInt16(BinaryReader reader)
    {
        return BinaryPrimitives.ReadUInt16BigEndian(reader.ReadBytes(2));
    }

    private static uint ReadUInt32(BinaryReader reader)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(reader.ReadBytes(4));
    }

    private static ulong ReadUInt64(BinaryReader reader)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(reader.ReadBytes(8));
    }
}
