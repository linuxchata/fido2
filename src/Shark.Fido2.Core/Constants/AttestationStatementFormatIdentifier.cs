using System.Collections.Generic;

namespace Shark.Fido2.Core.Constants
{
    /// <summary>
    /// WebAuthn Attestation Statement Format Identifiers
    /// https://www.iana.org/assignments/webauthn/webauthn.xhtml
    /// </summary>
    internal static class AttestationStatementFormatIdentifier
    {
        public const string Packed = "packed";

        public const string Tpm = "tpm";

        public const string AndroidKey = "android-key";

        public const string AndroidSafetynet = "android-safetynet";

        public const string FidoU2f = "fido-u2f";

        public const string Apple = "apple";

        public const string None = "none";

        public readonly static HashSet<string> Supported = new HashSet<string>
        {
            Packed, Tpm, AndroidKey, AndroidSafetynet, FidoU2f, Apple, None
        };
    }
}
