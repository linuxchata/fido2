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

        /// <summary>
        /// The RSA modulus n
        /// </summary>
        public byte[]? Modulus { get; set; }

        /// <summary>
        /// The RSA public exponent e
        /// </summary>
        public byte[]? Exponent { get; set; }

        /// <summary>
        /// Elliptic Curves
        /// </summary>
        public int? Curve { get; set; }

        /// <summary>
        /// X-coordinate for the EC point
        /// </summary>
        public byte[]? XCoordinate { get; set; }

        /// <summary>
        /// Y-coordinate for the EC point
        /// </summary>
        public byte[]? YCoordinate { get; set; }
    }
}
