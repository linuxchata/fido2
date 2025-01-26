using System.Buffers.Binary;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// 8.3. TPM Attestation Statement Format
/// </summary>
internal class TpmAttestationStatementStrategy : IAttestationStatementStrategy
{
    private const string PubArea = "pubArea";

    public ValidatorInternalResult Validate(
        AttestationObjectData attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        var attestationStatement = attestationObjectData.AttestationStatement ??
            throw new ArgumentNullException(nameof(attestationObjectData));

        if (attestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("Attestation statement cannot be read", nameof(attestationObjectData));
        }

        if (!attestationStatementDict.TryGetValue(PubArea, out var pubArea) || pubArea is not byte[])
        {
            return ValidatorInternalResult.Invalid("Attestation statement pubArea cannot be read");
        }

        using var stream = new MemoryStream((byte[])pubArea);
        using var reader = new BinaryReader(stream);

        var tpmtPublic = new Domain.Tpm.TpmtPublic();

        tpmtPublic.Type = (TpmAlgorithmEnum)ReadUInt16(reader); // TPMI_ALG_PUBLIC => TPM_ALG_ID; UINT16
        tpmtPublic.NameAlg = ReadUInt16(reader); // TPMI_ALG_HASH => TPM_ALG_ID; UINT16
        tpmtPublic.ObjectAttributes = ReadUInt32(reader); // TPMA_OBJECT; UINT32

        var authPolicySize = ReadUInt16(reader); // TPM2B_DIGEST; size is UINT16
        tpmtPublic.AuthPolicy = reader.ReadBytes(authPolicySize);

        if (tpmtPublic.Type == TpmAlgorithmEnum.TpmAlgorithmRsa)
        {
            var symmetric = ReadUInt16(reader);
            var scheme = ReadUInt16(reader);

            var keyBits = ReadUInt16(reader); // TPMI_RSA_KEY_BITS => TPM_KEY_BITS; UINT16
            var exponent = ReadUInt32(reader); // TPMS_RSA_PARMS; UINT32
            if (exponent == 0)
            {
                exponent = (uint)(Math.Pow(2, 16) + 1);
            }

            var size = ReadUInt16(reader);
            var modulus = reader.ReadBytes(size);
        }

        return new AttestationStatementInternalResult(AttestationTypeEnum.AttCA);
    }

    private ushort ReadUInt16(BinaryReader reader)
    {
        return BinaryPrimitives.ReadUInt16BigEndian(reader.ReadBytes(2));
    }

    private uint ReadUInt32(BinaryReader reader)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(reader.ReadBytes(4));
    }
}
