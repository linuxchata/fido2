using System;
using System.Buffers.Binary;
using System.Collections;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Models;

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

        public AuthenticatorDataModel? Get(byte[]? authenticatorData)
        {
            if (authenticatorData == null)
            {
                return null;
            }

            var result = new AuthenticatorDataModel();

            var startIndex = 0;

            // rpIdHash
            var rpIdHashArray = authenticatorData.AsSpan(startIndex, RpIdHashLength);
            result.RpIdHash = rpIdHashArray.ToArray();

            // Flags
            startIndex += RpIdHashLength;
            var flagsArray = authenticatorData.AsSpan(startIndex, FlagsLength);
            GetFlags(flagsArray[0], result);
            result.Flags = flagsArray[0];

            // Signature Counter
            startIndex += FlagsLength;
            var signCountArray = authenticatorData.AsSpan(startIndex, SignCountLength);
            var signCount = BinaryPrimitives.ReadUInt32BigEndian(signCountArray);
            result.SignCount = signCount;

            // AAGUID of the authenticator
            startIndex += SignCountLength;
            var aaguidArray = authenticatorData.AsSpan(startIndex, AaguidLength);
            result.AttestedCredentialData.AaGuid = new Guid(aaguidArray);

            // Credential ID Length
            startIndex += AaguidLength;
            var credentialIdLengthArray = authenticatorData.AsSpan(startIndex, CredentialIdLengthLength);
            var credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(credentialIdLengthArray);

            // Credential ID
            startIndex += credentialIdLength;
            var credentialId = authenticatorData.AsSpan(startIndex, credentialIdLength);
            result.AttestedCredentialData.CredentialId = credentialId.ToArray();

            return result;
        }

        private void GetFlags(byte flag, AuthenticatorDataModel authenticatorData)
        {
            authenticatorData.UserPresent = (flag & 0b00000001) != 0;
            authenticatorData.UserVerified = (flag & 0b00000100) != 0;
            authenticatorData.AttestedCredentialDataIncluded = (flag & 0b01000000) != 0;
            authenticatorData.ExtensionDataIncluded = (flag & 0b10000000) != 0;
        }
    }
}
