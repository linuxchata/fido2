namespace Shark.Fido2.Domain
{
    public class Credential
    {
        public byte[] CredentialId { get; set; } = null!;

        /// <summary>
        /// Credential Public Key
        /// </summary>
        public CredentialPublicKey CredentialPublicKey { get; set; } = null!;

        /// <summary>
        /// Signature Counter
        /// </summary>
        public uint SignCount { get; set; }
    }
}
