namespace Shark.Fido2.Core.Models
{
    public sealed class AuthenticatorDataModel
    {
        /// <summary>
        /// SHA-256 hash of the RP ID the credential is scoped to.
        /// </summary>
        public byte[] RpIdHash { get; set; } = null!;

        /// <summary>
        /// Flags
        /// </summary>
        public byte Flags { get; set; }

        /// <summary>
        /// Signature counter
        /// </summary>
        public uint SignCount { get; set; }

        public string AttestedCredentialData { get; set; } = null!;

        public string Extensions { get; set; } = null!;
    }
}
