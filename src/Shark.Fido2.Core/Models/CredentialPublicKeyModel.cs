namespace Shark.Fido2.Core.Models
{
    /// <summary>
    /// Credential Public Key
    /// </summary>
    public sealed class CredentialPublicKeyModel
    {
        /// <summary>
        /// Cryptographic signature algorithm
        /// </summary>
        public long? Algorithm { get; set; }
    }
}
