using System;
using System.Buffers.Binary;
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

            var startIndex = 0;
            var rpIdHashArray = authenticatorData.AsSpan(startIndex, RpIdHashLength).ToArray();

            startIndex += RpIdHashLength + 1;
            var flagsArray = authenticatorData.AsSpan(startIndex, FlagsLength).ToArray();

            startIndex += FlagsLength + 1;
            var signCountArray = authenticatorData.AsSpan(startIndex, SignCountLength).ToArray();
            var signCount = BinaryPrimitives.ReadUInt32BigEndian(signCountArray);

            startIndex += SignCountLength + 1;
            var aaguidArray = authenticatorData.AsSpan(startIndex, AaguidLength).ToArray();

            startIndex += AaguidLength + 1;
            var credentialIdLengthArray = authenticatorData.AsSpan(startIndex, CredentialIdLengthLength).ToArray();
            var credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(credentialIdLengthArray);

            GetFlags(flagsArray[0]);

            return new AuthenticatorDataModel
            {
                RpIdHash = rpIdHashArray,
                Flags = flagsArray[0],
                SignCount = signCount,
            };
        }

        private void GetFlags(byte flag)
        {
            var userPresent = (flag & 0b00000001) != 0;
            var userVerified = (flag & 0b00000100) != 0;
            var attestedCredentialData = (flag & 0b01000000) != 0;
            var extensionDataIncluded = (flag & 0b10000000) != 0;
        }
    }
}
