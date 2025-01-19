namespace Shark.Fido2.Domain.Enums
{
    /// <summary>
    /// COSE Algorithms
    /// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    /// </summary>
    public enum PublicKeyAlgorithm
    {
        /// <summary>
        /// ECDSA w/ SHA-256
        /// </summary>
        Es256 = -7,

        /// <summary>
        /// EdDSA
        /// </summary>
        EdDsa = -8,

        /// <summary>
        /// ECDSA w/ SHA-384
        /// </summary>
        Es384 = -35,

        // ECDSA w/ SHA-512
        Es512 = -36,

        /// <summary>
        /// RSASSA-PSS w/ SHA-256
        /// </summary>
        Ps256 = -37,

        /// <summary>
        /// RSASSA-PSS w/ SHA-384
        /// </summary>
        PS384 = -38,

        /// <summary>
        /// RSASSA-PSS w/ SHA-512
        /// </summary>
        PS512 = -39,

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-256
        /// </summary>
        Rs256 = -257,
    }
}
