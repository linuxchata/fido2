namespace Shark.Fido2.Domain
{
    /// <summary>
    /// Credential Public Key
    /// </summary>
    public sealed class CredentialPublicKey
    {
        /// <summary>
        /// Cryptographic signature algorithm
        /// </summary>
        public long? Algorithm { get; set; }
    }
}
