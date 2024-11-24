namespace Shark.Fido2.Core.Models
{
    public sealed class AuthenticatorDataModel
    {
        public AuthenticatorDataModel()
        {
            AttestedCredentialData = new AttestedCredentialDataModel();
        }

        /// <summary>
        /// SHA-256 hash of the RP ID the credential is scoped to.
        /// </summary>
        public byte[] RpIdHash { get; set; } = null!;

        /// <summary>
        /// Flags
        /// </summary>
        public byte Flags { get; set; }

        /// <summary>
        /// User Present
        /// </summary>
        public bool UserPresent { get; set; }

        /// <summary>
        /// User Verified
        /// </summary>
        public bool UserVerified { get; set; }

        /// <summary>
        /// Attested credential data included
        /// </summary>
        public bool AttestedCredentialDataIncluded { get; set; }

        /// <summary>
        /// Extension data included
        /// </summary>
        public bool ExtensionDataIncluded { get; set; }

        /// <summary>
        /// Signature Counter
        /// </summary>
        public uint SignCount { get; set; }

        /// <summary>
        /// Attested Credential Data
        /// </summary>
        public AttestedCredentialDataModel AttestedCredentialData { get; set; }

        public string Extensions { get; set; } = null!;
    }
}
