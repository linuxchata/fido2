using System;

namespace Shark.Fido2.Domain
{
    /// <summary>
    /// Attested Credential Data
    /// </summary>
    public sealed class AttestedCredentialData
    {
        public AttestedCredentialData()
        {
            CredentialPublicKey = new CredentialPublicKey();
        }

        /// <summary>
        /// The AAGUID of the authenticator
        /// </summary>
        public Guid AaGuid { get; set; }

        /// <summary>
        /// Credential ID
        /// </summary>
        public byte[] CredentialId { get; set; } = null!;

        /// <summary>
        /// The credential public key
        /// </summary>
        public CredentialPublicKey CredentialPublicKey { get; set; } = null!;
    }
}
