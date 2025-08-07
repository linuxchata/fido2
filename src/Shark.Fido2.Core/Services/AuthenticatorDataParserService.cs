using System.Buffers.Binary;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Services;

/// <summary>
/// Authenticator Data provider
/// See: 6.1. Authenticator Data of Web Authentication: An API for accessing Public Key Credentials Level 2.
/// </summary>
internal sealed class AuthenticatorDataParserService : IAuthenticatorDataParserService
{
    private const int RpIdHashLength = 32;
    private const int FlagsLength = 1;
    private const int SignCountLength = 4;
    private const int AaguidLength = 16;
    private const int CredentialIdLengthLength = 2;

    public AuthenticatorData? Parse(byte[]? authenticatorDataArray)
    {
        ArgumentNullException.ThrowIfNull(authenticatorDataArray, nameof(authenticatorDataArray));

        var authenticatorData = new AuthenticatorData
        {
            AttestedCredentialData = new AttestedCredentialData(),
        };

        var startIndex = 0;

        // Relying Party Identifier Hash
        var rpIdHashArray = authenticatorDataArray.AsSpan(startIndex, RpIdHashLength);
        authenticatorData.RpIdHash = rpIdHashArray.ToArray();
        startIndex += RpIdHashLength;

        // Flags
        var flagsArray = authenticatorDataArray.AsSpan(startIndex, FlagsLength);
        GetAndSetFlags(flagsArray[0], authenticatorData);
        authenticatorData.Flags = flagsArray[0];
        startIndex += FlagsLength;

        // Signature Counter
        var signCountArray = authenticatorDataArray.AsSpan(startIndex, SignCountLength);
        var signCount = BinaryPrimitives.ReadUInt32BigEndian(signCountArray);
        authenticatorData.SignCount = signCount;
        startIndex += SignCountLength;

        if (authenticatorData.AttestedCredentialDataIncluded)
        {
            // The authenticator attestation GUID
            var aaguidArray = authenticatorDataArray.AsSpan(startIndex, AaguidLength);
            authenticatorData.AttestedCredentialData.AaGuid = new Guid(aaguidArray, bigEndian: true);
            startIndex += AaguidLength;

            // Credential ID Length
            var credentialIdLengthArray = authenticatorDataArray.AsSpan(startIndex, CredentialIdLengthLength);
            var credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(credentialIdLengthArray);
            startIndex += CredentialIdLengthLength;

            // Credential ID
            var credentialId = authenticatorDataArray.AsSpan(startIndex, credentialIdLength);
            authenticatorData.AttestedCredentialData.CredentialId = credentialId.ToArray();
            startIndex += credentialIdLength;

            // Credential Public Key
            var credentialPublicKeyBytesRemaining = 0;
            var credentialPublicKeyLength = authenticatorDataArray.Length - startIndex;
            var credentialPublicKeyArray = authenticatorDataArray.AsSpan(startIndex, credentialPublicKeyLength);
            var credentialPublicKey = GetCredentialPublicKey(credentialPublicKeyArray, ref credentialPublicKeyBytesRemaining);
            authenticatorData.AttestedCredentialData.CredentialPublicKey = credentialPublicKey;
            startIndex += credentialPublicKeyLength - credentialPublicKeyBytesRemaining;
        }

        var extensionDataBytesRemaining = 0;
        if (authenticatorData.ExtensionDataIncluded)
        {
            var leftoverBytes = authenticatorDataArray.Length - startIndex;
            var extensionLength = authenticatorDataArray.AsSpan(startIndex, leftoverBytes);
            if (extensionLength.Length > 0)
            {
                CborConverter.Decode(extensionLength.ToArray(), ref extensionDataBytesRemaining);
            }

            startIndex += extensionLength.Length - extensionDataBytesRemaining;
        }

        if (startIndex != authenticatorDataArray.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(authenticatorDataArray),
                "Attestation data contains leftover bytes");
        }

        return authenticatorData;
    }

    private CredentialPublicKey GetCredentialPublicKey(Span<byte> credentialPublicKeyArray, ref int bytesRemaining)
    {
        var coseKeyFormat = CborConverter.DecodeToCoseKeyFormat(credentialPublicKeyArray.ToArray(), ref bytesRemaining);

        var credentialPublicKey = new CredentialPublicKey
        {
            KeyType = GetCredentialPublicKeyIntParameter(coseKeyFormat, CoseKeyIndex.KeyType),
            Algorithm = GetCredentialPublicKeyIntParameter(coseKeyFormat, CoseKeyIndex.Algorithm),
        };

        if (credentialPublicKey.KeyType == (int)KeyType.Okp)
        {
            // https://datatracker.ietf.org/doc/html/rfc8152#section-13.2
            credentialPublicKey.Curve = GetCredentialPublicKeyIntNullableParameter(coseKeyFormat, CoseKeyIndex.Curve);
            credentialPublicKey.XCoordinate = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.XCoordinate);
        }
        else if (credentialPublicKey.KeyType == (int)KeyType.Ec2)
        {
            // https://datatracker.ietf.org/doc/html/rfc8152#section-13.1
            credentialPublicKey.Curve = GetCredentialPublicKeyIntNullableParameter(coseKeyFormat, CoseKeyIndex.Curve);
            credentialPublicKey.XCoordinate = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.XCoordinate);
            credentialPublicKey.YCoordinate = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.YCoordinate);
        }
        else if (credentialPublicKey.KeyType == (int)KeyType.Rsa)
        {
            // https://datatracker.ietf.org/doc/html/rfc8230#section-4
            credentialPublicKey.Modulus = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.Modulus);
            credentialPublicKey.Exponent = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.Exponent);
        }
        else if (credentialPublicKey.KeyType == (int)KeyType.Symmetric)
        {
            // https://datatracker.ietf.org/doc/html/rfc8152#section-13.3
            credentialPublicKey.Key = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.SymmetricKey);
        }
        else
        {
            throw new NotSupportedException("Unsupported key type");
        }

        return credentialPublicKey;
    }

    private static void GetAndSetFlags(byte flags, AuthenticatorData authenticatorData)
    {
        authenticatorData.UserPresent = (flags & 0b00000001) != 0; // Bit 0
        authenticatorData.UserVerified = (flags & 0b00000100) != 0; // Bit 2
        authenticatorData.AttestedCredentialDataIncluded = (flags & 0b01000000) != 0; // Bit 6
        authenticatorData.ExtensionDataIncluded = (flags & 0b10000000) != 0; // Bit 7
    }

    private static int GetCredentialPublicKeyIntParameter(Dictionary<int, object> coseKeyFormat, int coseKeyIndex)
    {
        if (coseKeyFormat.TryGetValue(coseKeyIndex, out var value))
        {
            return Convert.ToInt32(value);
        }

        throw new ArgumentException("COSE key format does not expected key index", nameof(coseKeyFormat));
    }

    private static int? GetCredentialPublicKeyIntNullableParameter(Dictionary<int, object> coseKeyFormat, int coseKeyIndex)
    {
        if (coseKeyFormat.TryGetValue(coseKeyIndex, out var value))
        {
            return Convert.ToInt32(value);
        }

        return null;
    }

    private static byte[]? GetCredentialPublicKeyParameter(Dictionary<int, object> coseKeyFormat, int coseKeyIndex)
    {
        if (coseKeyFormat.TryGetValue(coseKeyIndex, out var value))
        {
            return (byte[])value;
        }

        return null;
    }
}
