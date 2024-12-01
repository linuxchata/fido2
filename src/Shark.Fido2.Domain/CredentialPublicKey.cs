namespace Shark.Fido2.Domain
{
    /// <summary>
    /// Credential Public Key
    /// </summary>
    public sealed class CredentialPublicKey
    {
        /// <summary>
        /// Identification of the key type (kty)
        /// </summary>
        public int? KeyType { get; set; }

        /// <summary>
        /// Cryptographic signature algorithm (alg)
        /// </summary>
        public int? Algorithm { get; set; }
    }
}
