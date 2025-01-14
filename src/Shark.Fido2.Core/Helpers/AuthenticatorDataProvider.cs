﻿using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Enums;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Helpers
{
    /// <summary>
    /// Authenticator Data provider
    /// See 6.1. Authenticator Data of Web Authentication: An API for accessing Public Key Credentials Level 2
    /// </summary>
    internal class AuthenticatorDataProvider : IAuthenticatorDataProvider
    {
        private const int RpIdHashLength = 32;
        private const int FlagsLength = 1;
        private const int SignCountLength = 4;
        private const int AaguidLength = 16;
        private const int CredentialIdLengthLength = 2;

        public AuthenticatorData? Get(byte[]? authenticatorDataArray)
        {
            if (authenticatorDataArray == null)
            {
                return null;
            }

            var authenticatorData = new AuthenticatorData();

            var startIndex = 0;

            // Relying Party Identifier Hash
            var rpIdHashArray = authenticatorDataArray.AsSpan(startIndex, RpIdHashLength);
            authenticatorData.RpIdHash = rpIdHashArray.ToArray();

            // Flags
            startIndex += RpIdHashLength;
            var flagsArray = authenticatorDataArray.AsSpan(startIndex, FlagsLength);
            GetAndSetFlags(flagsArray[0], authenticatorData);
            authenticatorData.Flags = flagsArray[0];

            // Signature Counter
            startIndex += FlagsLength;
            var signCountArray = authenticatorDataArray.AsSpan(startIndex, SignCountLength);
            var signCount = BinaryPrimitives.ReadUInt32BigEndian(signCountArray);
            authenticatorData.SignCount = signCount;

            // AAGUID of the authenticator
            startIndex += SignCountLength;
            var aaguidArray = authenticatorDataArray.AsSpan(startIndex, AaguidLength);
            authenticatorData.AttestedCredentialData.AaGuid = new Guid(aaguidArray);

            // Credential ID Length
            startIndex += AaguidLength;
            var credentialIdLengthArray = authenticatorDataArray.AsSpan(startIndex, CredentialIdLengthLength);
            var credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(credentialIdLengthArray);

            // Credential ID
            startIndex += CredentialIdLengthLength;
            var credentialId = authenticatorDataArray.AsSpan(startIndex, credentialIdLength);
            authenticatorData.AttestedCredentialData.CredentialId = credentialId.ToArray();

            // Credential Public Key
            startIndex += credentialIdLength;
            var credentialPublicKeyLength = authenticatorDataArray.Length - startIndex;
            var credentialPublicKeyArray = authenticatorDataArray.AsSpan(startIndex, credentialPublicKeyLength);
            var credentialPublicKey = GetCredentialPublicKey(credentialPublicKeyArray);
            authenticatorData.AttestedCredentialData.CredentialPublicKey = credentialPublicKey;

            return authenticatorData;
        }

        private void GetAndSetFlags(byte flags, AuthenticatorData authenticatorData)
        {
            authenticatorData.UserPresent = (flags & 0b00000001) != 0; // Bit 0
            authenticatorData.UserVerified = (flags & 0b00000100) != 0; // Bit 2
            authenticatorData.AttestedCredentialDataIncluded = (flags & 0b01000000) != 0; // Bit 6
            authenticatorData.ExtensionDataIncluded = (flags & 0b10000000) != 0; // Bit 7
        }

        private CredentialPublicKey GetCredentialPublicKey(Span<byte> credentialPublicKeyArray)
        {
            var coseKeyFormat = CborConverter.DecodeToCoseKeyFormat(credentialPublicKeyArray.ToArray());

            var credentialPublicKey = new CredentialPublicKey
            {
                KeyType = GetCredentialPublicKeyIntParameter(coseKeyFormat, CoseKeyIndex.KeyType),
                Algorithm = GetCredentialPublicKeyIntParameter(coseKeyFormat, CoseKeyIndex.Algorithm),
            };

            if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Rsa)
            {
                // https://datatracker.ietf.org/doc/html/rfc8230#section-4
                credentialPublicKey.Modulus = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.Modulus);
                credentialPublicKey.Exponent = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.Exponent);
            }
            else if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Ec2)
            {
                // https://datatracker.ietf.org/doc/html/rfc8152#section-13.1
                credentialPublicKey.Curve = GetCredentialPublicKeyIntParameter(coseKeyFormat, CoseKeyIndex.Curve);
                credentialPublicKey.XCoordinate = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.XCoordinate);
                credentialPublicKey.YCoordinate = GetCredentialPublicKeyParameter(coseKeyFormat, CoseKeyIndex.YCoordinate);
            }

            return credentialPublicKey;
        }

        private int? GetCredentialPublicKeyIntParameter(
            Dictionary<int, object> coseKeyFormat,
            int coseKeyAlgorithmIndex)
        {
            if (coseKeyFormat.TryGetValue(coseKeyAlgorithmIndex, out var value))
            {
                return Convert.ToInt32(value);
            };

            return null;
        }

        private byte[]? GetCredentialPublicKeyParameter(
            Dictionary<int, object> coseKeyFormat,
            int coseKeyAlgorithmIndex)
        {
            if (coseKeyFormat.TryGetValue(coseKeyAlgorithmIndex, out var value))
            {
                return (byte[])value;
            };

            return null;
        }
    }
}
