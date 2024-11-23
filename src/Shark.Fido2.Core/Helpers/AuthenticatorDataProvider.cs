using System;
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

        public AuthenticatorDataModel Get(byte[] authenticatorData)
        {
            var startIndex = 0;
            var rpIdHash = authenticatorData.AsSpan(startIndex, RpIdHashLength).ToArray();

            startIndex += RpIdHashLength + 1;
            var flags = authenticatorData.AsSpan(startIndex, FlagsLength).ToArray();

            startIndex += FlagsLength + 1;
            var signCountArray = authenticatorData.AsSpan(startIndex, SignCountLength).ToArray();
            var signCount = BitConverter.ToUInt32(signCountArray);

            return new AuthenticatorDataModel
            {
                RpIdHash = rpIdHash,
                Flags = flags[0],
                SignCount = signCount,
            };
        }
    }
}
