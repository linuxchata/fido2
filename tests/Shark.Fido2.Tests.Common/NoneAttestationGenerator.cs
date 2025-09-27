using System.Formats.Cbor;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Tests.Common;

public static class NoneAttestationGenerator
{
    public static string GenerateAttestationObject(AuthenticatorData sourceAuthenticatorData, byte[] credentialId)
    {
        var encodeCredentialPublicKey = EncodeCredentialPublicKey(
            sourceAuthenticatorData!.AttestedCredentialData!.CredentialPublicKey!);

        var attestationObject = GenerateInternal(
            sourceAuthenticatorData!.RpIdHash!,
            sourceAuthenticatorData.AttestedCredentialData!.AaGuid,
            credentialId,
            encodeCredentialPublicKey);

        return attestationObject;
    }

    private static string GenerateInternal(
        byte[] rpIdHash,
        Guid aaGuidValue,
        byte[] credentialId,
        byte[] credentialPublicKey)
    {
        // Flags (User Present + User Verified + AttestedCredentialDataIncluded + ExtensionDataIncluded)
        byte flags = 0x5D;

        // Signature counter (4 bytes, big endian)
        byte[] signCount = [0x00, 0x00, 0x00, 0x00];

        // Attested Credential Data
        var aaguid = GuidToBigEndianBytes(aaGuidValue);
        var credentialIdLength = BitConverter.GetBytes((ushort)credentialId.Length);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(credentialIdLength);
        }

        var attestedCredentialData = Combine(aaguid, credentialIdLength, credentialId, credentialPublicKey);

        // Final authData
        var authData = Combine(rpIdHash, [flags], signCount, attestedCredentialData);

        // Encode attestationObject
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        // attestationObject is a CBOR map with 3 entries
        writer.WriteStartMap(3);

        // fmt: "none"
        writer.WriteTextString("fmt");
        writer.WriteTextString("none");

        // authData: byte string
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);

        // attStmt: empty map
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        writer.WriteEndMap();

        var attestationObject = writer.Encode();

        return attestationObject.ToBase64Url();
    }

    private static byte[] EncodeCredentialPublicKey(CredentialPublicKey credentialPublicKey)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        // 5 entries in the map
        writer.WriteStartMap(5);

        // kty
        writer.WriteInt32(1);
        writer.WriteInt32(credentialPublicKey.KeyType);

        // alg
        writer.WriteInt32(3);
        writer.WriteInt32(credentialPublicKey.Algorithm);

        // crv
        if (credentialPublicKey.Curve.HasValue)
        {
            writer.WriteInt32(-1);
            writer.WriteInt32(credentialPublicKey.Curve!.Value);
        }

        // x coordinate
        if (credentialPublicKey.XCoordinate != null)
        {
            writer.WriteInt32(-2);
            writer.WriteByteString(credentialPublicKey.XCoordinate!);
        }

        // y coordinate
        if (credentialPublicKey.YCoordinate != null)
        {
            writer.WriteInt32(-3);
            writer.WriteByteString(credentialPublicKey.YCoordinate!);
        }

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] GuidToBigEndianBytes(Guid guid)
    {
        var bytes = guid.ToByteArray();

        byte[] bigEndian = new byte[16];

        // Part 1 (4 bytes) – reverse
        bigEndian[0] = bytes[3];
        bigEndian[1] = bytes[2];
        bigEndian[2] = bytes[1];
        bigEndian[3] = bytes[0];

        // Part 2 (2 bytes) – reverse
        bigEndian[4] = bytes[5];
        bigEndian[5] = bytes[4];

        // Part 3 (2 bytes) – reverse
        bigEndian[6] = bytes[7];
        bigEndian[7] = bytes[6];

        // Part 4 (8 bytes)
        Buffer.BlockCopy(bytes, 8, bigEndian, 8, 8);

        return bigEndian;
    }

    private static byte[] Combine(params byte[][] arrays)
    {
        var length = 0;
        foreach (var arr in arrays)
        {
            length += arr.Length;
        }

        var result = new byte[length];
        var offset = 0;
        foreach (var arr in arrays)
        {
            Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
            offset += arr.Length;
        }

        return result;
    }
}
